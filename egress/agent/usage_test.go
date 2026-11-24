package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// -- protobuf encoding for the fake API service ------------------------------------------------------------------

func pbKey(num, wire int) []byte { return binary.AppendUvarint(nil, uint64(num<<3|wire)) }
func pbInt(num int, v int64) []byte {
	return append(pbKey(num, 0), binary.AppendUvarint(nil, uint64(v))...)
}
func pbBytes(num int, b []byte) []byte {
	out := append(pbKey(num, 2), binary.AppendUvarint(nil, uint64(len(b)))...)
	return append(out, b...)
}
func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

type fakeConn struct {
	id, user        string
	up, down        int64
	closedAt        int64
	withoutMetadata bool // a CLOSED event that lost its connection (sing-box sends one when metadata is gone)
}

func connMsg(c fakeConn) []byte {
	return cat(pbBytes(1, []byte(c.id)), pbBytes(2, []byte("user-x")), pbBytes(3, []byte("vless")),
		pbBytes(10, []byte(c.user)), pbInt(13, c.closedAt), pbInt(16, c.up), pbInt(17, c.down))
}

func eventNewMsg(c fakeConn) []byte {
	return pbBytes(1, cat(pbInt(1, eventNew), pbBytes(2, []byte(c.id)), pbBytes(3, connMsg(c))))
}
func eventClosedMsg(c fakeConn) []byte {
	if c.withoutMetadata {
		return pbBytes(1, cat(pbInt(1, eventClosed), pbBytes(2, []byte(c.id)), pbInt(6, c.closedAt)))
	}
	return pbBytes(1, cat(pbInt(1, eventClosed), pbBytes(2, []byte(c.id)), pbBytes(3, connMsg(c)), pbInt(6, c.closedAt)))
}
func eventUpdateMsg(id string, up, down int64) []byte {
	return pbBytes(1, cat(pbInt(1, eventUpdate), pbBytes(2, []byte(id)), pbInt(4, up), pbInt(5, down)))
}

// resetMsg is a subscription's first message: open and remembered closed connections.
func resetMsg(conns ...fakeConn) []byte {
	var out []byte
	for _, c := range conns {
		out = append(out, eventNewMsg(c)...)
	}
	return append(out, pbInt(2, 1)...)
}

// fakeAPI imitates sing-box's API service: GetStartedAt and SubscribeConnections over gRPC-web.
type fakeAPI struct {
	t        *testing.T
	srv      *httptest.Server
	mu       sync.Mutex
	instance int64
	secret   string
	streams  chan chan []byte // each subscription takes the next scripted stream
	subs     int
	clash    string // secret the fake Clash API accepts; "" answers 401
	marker   string // confirmation marker the fake Clash API lists
	bumpOnce bool   // the next GetStartedAt after a subscription reports a new instance (a restart mid-subscribe)
}

func newFakeAPI(t *testing.T, secret string) *fakeAPI {
	f := &fakeAPI{t: t, instance: 1000, secret: secret, streams: make(chan chan []byte, 16)}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) addr() string { return strings.TrimPrefix(f.srv.URL, "http://") }

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" && r.URL.Path == "/proxies" { // the Clash API on the same fake (confirmation evidence)
		f.mu.Lock()
		secret, marker := f.clash, f.marker
		f.mu.Unlock()
		if secret == "" || r.Header.Get("Authorization") != "Bearer "+secret {
			w.WriteHeader(401)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"proxies": map[string]any{marker: map[string]any{"type": "Reject"}}})
		return
	}
	if r.Header.Get("Content-Type") != "application/grpc-web+proto" || r.Method != "POST" {
		http.Error(w, "bad request", 400)
		return
	}
	io.ReadAll(r.Body)
	w.Header().Set("Content-Type", "application/grpc-web+proto")
	if r.Header.Get("Authorization") != "Bearer "+f.secret {
		w.Header().Set("Grpc-Status", "16")
		w.Header().Set("Grpc-Message", "invalid authorization")
		w.WriteHeader(200)
		return
	}
	flusher := w.(http.Flusher)
	switch r.URL.Path {
	case "/daemon.StartedService/GetStartedAt":
		f.mu.Lock()
		if f.bumpOnce && f.subs > 0 {
			f.instance, f.bumpOnce = f.instance+1, false
		}
		instance := f.instance
		f.mu.Unlock()
		w.Write(grpcFrame(pbInt(1, instance)))
		w.Write(append([]byte{0x80, 0, 0, 0, 16}, []byte("grpc-status: 0\r\n")...))
	case "/daemon.StartedService/SubscribeConnections":
		f.mu.Lock()
		f.subs++
		f.mu.Unlock()
		var stream chan []byte
		select {
		case stream = <-f.streams:
		case <-r.Context().Done():
			return
		}
		w.WriteHeader(200)
		flusher.Flush()
		for {
			select {
			case msg, ok := <-stream:
				if !ok {
					return // EOF: the instance stopped
				}
				w.Write(grpcFrame(msg))
				flusher.Flush()
			case <-r.Context().Done():
				return
			}
		}
	default:
		http.Error(w, "no route", 404)
	}
}

func (f *fakeAPI) setInstance(v int64) { f.mu.Lock(); f.instance = v; f.mu.Unlock() }

// -- collector under test ---------------------------------------------------------------------------------------

type sentReport struct {
	payload map[string]any
}

type usageHarness struct {
	t      *testing.T
	c      *usageCollector
	api    *fakeAPI
	dir    string
	mu     sync.Mutex
	sent   []sentReport
	answer int // HTTP status the fake control plane returns
	clock  time.Time
}

func newUsageHarness(t *testing.T, dir string) *usageHarness {
	t.Setenv("CCPROXY_FAKE_SINGBOX", "1")
	exe, _ := os.Executable()
	if dir == "" {
		dir = t.TempDir()
	}
	h := &usageHarness{t: t, dir: dir, answer: 200, clock: time.Date(2026, 11, 23, 15, 59, 0, 0, time.UTC)}
	a := &Agent{opt: Options{StateDir: dir, Config: filepath.Join(dir, "config.json"), SingBox: exe,
		UsageAPI: "127.0.0.1:1", UsageInterval: 60, ConfirmAPI: "127.0.0.1:2"}, logf: t.Logf, confirmAddress: "127.0.0.1:2"}
	c, err := newUsageCollector(a)
	if err != nil {
		t.Fatal(err)
	}
	if !c.supported {
		t.Fatalf("fake sing-box should support the API service: %s", c.disabled)
	}
	h.api = newFakeAPI(t, c.st.Secret)
	c.addr = h.api.addr()
	c.now = func() time.Time { h.mu.Lock(); defer h.mu.Unlock(); return h.clock }
	c.sendFn = func(payload map[string]any) (int, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		data, _ := json.Marshal(payload) // what goes on the wire
		var copied map[string]any
		json.Unmarshal(data, &copied)
		h.sent = append(h.sent, sentReport{copied})
		if h.answer != 200 {
			return h.answer, fmt.Errorf("HTTP %d", h.answer)
		}
		return 200, nil
	}
	c.injected = true
	h.c = c
	return h
}

func (h *usageHarness) advance(d time.Duration) { h.mu.Lock(); h.clock = h.clock.Add(d); h.mu.Unlock() }

func (h *usageHarness) writeConfig(users ...string) {
	var list []any
	for _, u := range users {
		list = append(list, map[string]any{"name": u, "uuid": "00000000-0000-4000-8000-000000000000"})
	}
	data, _ := json.Marshal(map[string]any{"inbounds": []any{map[string]any{"type": "vless", "tag": "user-x", "users": list}}})
	if err := os.WriteFile(h.c.agent.opt.Config, data, 0o600); err != nil {
		h.t.Fatal(err)
	}
}

// subscription runs one subscribeOnce against a scripted stream and returns the channel to feed it.
func (h *usageHarness) subscription() (chan []byte, chan error) {
	stream := make(chan []byte)
	h.api.streams <- stream
	done := make(chan error, 1)
	go func() { done <- h.c.subscribeOnce(h.t.Context()) }()
	return stream, done
}

func (h *usageHarness) send(stream chan []byte, msg []byte) {
	select {
	case stream <- msg:
	case <-time.After(5 * time.Second):
		h.t.Fatal("the collector did not read the stream")
	}
	h.settle()
}

// settle waits until the collector processed what was written (the fake writes synchronously per message).
func (h *usageHarness) settle() {
	time.Sleep(30 * time.Millisecond)
	h.c.mu.Lock()
	h.c.mu.Unlock()
}

func (h *usageHarness) end(stream chan []byte, done chan error) {
	close(stream)
	select {
	case err := <-done:
		if err != nil {
			h.t.Fatalf("subscription ended with %v", err)
		}
	case <-time.After(5 * time.Second):
		h.t.Fatal("subscription did not end")
	}
}

// totals sums the unsent and in-flight hours per device: [up, down, cut].
func (h *usageHarness) totals() map[string][3]int64 {
	h.c.mu.Lock()
	defer h.c.mu.Unlock()
	out := map[string][3]int64{}
	add := func(hr *usageHour) {
		for name, b := range hr.Devices {
			v := out[name]
			out[name] = [3]int64{v[0] + b.Up, v[1] + b.Down, v[2] + b.Cut}
		}
		v := out[""]
		out[""] = [3]int64{v[0] + hr.Unattributed.Up, v[1] + hr.Unattributed.Down, v[2] + hr.Unattributed.Cut}
	}
	for _, hr := range h.c.st.Hours {
		add(hr)
	}
	if h.c.st.Batch != nil {
		for _, hr := range h.c.st.Batch.Hours {
			add(hr)
		}
	}
	return out
}

func (h *usageHarness) flags() (started, overflow bool, gap int64) {
	h.c.mu.Lock()
	defer h.c.mu.Unlock()
	for _, hr := range h.c.st.Hours {
		started, overflow, gap = started || hr.Started, overflow || hr.Overflow, gap+hr.GapSeconds
	}
	return
}

func wantBytes(t *testing.T, got map[string][3]int64, name string, up, down, cut int64) {
	t.Helper()
	if v := got[name]; v != [3]int64{up, down, cut} {
		t.Fatalf("%s: got up=%d down=%d cut=%d, want up=%d down=%d cut=%d (all: %v)", name, v[0], v[1], v[2], up, down, cut, got)
	}
}

// -- tests ------------------------------------------------------------------------------------------------------------

func TestUsageAttributesShortLivedConnectionsPerDevice(t *testing.T) {
	h := newUsageHarness(t, "")
	h.writeConfig("alice/mac", "alice/win", "bob/phone", "carol/idle")
	stream, done := h.subscription()
	h.send(stream, resetMsg()) // a fresh sing-box: nothing before history starts
	// Two devices of one user and a second user on the same exit, each with connections that open and close
	// between two update ticks: only NEW and CLOSED (with final totals) are ever seen.
	h.send(stream, cat(eventNewMsg(fakeConn{id: "a1", user: "alice/mac"}), eventNewMsg(fakeConn{id: "w1", user: "alice/win"})))
	h.send(stream, cat(eventClosedMsg(fakeConn{id: "a1", user: "alice/mac", up: 1000, down: 50000, closedAt: 1}),
		eventClosedMsg(fakeConn{id: "w1", user: "alice/win", up: 7, down: 9, closedAt: 1})))
	h.send(stream, eventNewMsg(fakeConn{id: "b1", user: "bob/phone"}))
	h.send(stream, eventUpdateMsg("b1", 300, 4000))
	h.send(stream, eventUpdateMsg("b1", 200, 1000))
	h.send(stream, eventClosedMsg(fakeConn{id: "b1", user: "bob/phone", up: 500, down: 5000, closedAt: 2}))
	h.end(stream, done)

	got := h.totals()
	wantBytes(t, got, "alice/mac", 1000, 50000, 0)
	wantBytes(t, got, "alice/win", 7, 9, 0)
	wantBytes(t, got, "bob/phone", 500, 5000, 0)
	wantBytes(t, got, "carol/idle", 0, 0, 0) // configured and measured: a measured zero
	wantBytes(t, got, "", 0, 0, 0)
	if started, _, _ := h.flags(); !started {
		t.Fatal("the first subscription must mark the start of history")
	}
}

func TestUsageFirstSnapshotIsABaselineNotTraffic(t *testing.T) {
	h := newUsageHarness(t, "")
	stream, done := h.subscription()
	h.send(stream, resetMsg(fakeConn{id: "old", user: "alice/mac", up: 1 << 20, down: 1 << 30},
		fakeConn{id: "gone", user: "alice/mac", up: 5, down: 5, closedAt: 9}))
	h.send(stream, eventUpdateMsg("old", 10, 20))
	h.end(stream, done)
	wantBytes(t, h.totals(), "alice/mac", 10, 20, 0)
}

func TestUsageResubscriptionRepairsDroppedEventsWithoutDoubleCounting(t *testing.T) {
	h := newUsageHarness(t, "")
	stream, done := h.subscription()
	h.send(stream, resetMsg())
	h.send(stream, eventNewMsg(fakeConn{id: "c1", user: "alice/mac"}))
	h.send(stream, eventUpdateMsg("c1", 100, 200))
	// The CLOSED event lost its metadata and "c2" was missed entirely (sing-box drops events for slow readers).
	h.send(stream, eventClosedMsg(fakeConn{id: "c1", closedAt: 5, withoutMetadata: true}))
	h.send(stream, eventNewMsg(fakeConn{id: "c3", user: "bob/phone"}))
	h.send(stream, eventUpdateMsg("c3", 1, 1))
	h.end(stream, done)

	// The next subscription's snapshot carries final totals for the closed ones and the open one.
	stream, done = h.subscription()
	snapshot := resetMsg(fakeConn{id: "c1", user: "alice/mac", up: 150, down: 260, closedAt: 5},
		fakeConn{id: "c2", user: "alice/mac", up: 40, down: 60, closedAt: 6},
		fakeConn{id: "c3", user: "bob/phone", up: 3, down: 4})
	h.send(stream, snapshot)
	h.end(stream, done)
	// A third, identical snapshot (a retry) adds nothing.
	stream, done = h.subscription()
	h.send(stream, snapshot)
	h.end(stream, done)

	got := h.totals()
	wantBytes(t, got, "alice/mac", 190, 320, 0)
	wantBytes(t, got, "bob/phone", 3, 4, 0)
	if _, overflow, gap := h.flags(); overflow || gap != 0 {
		t.Fatalf("no loss expected, got overflow=%v gap=%d", overflow, gap)
	}
}

func TestUsageReloadResetsCountersAndReportsCutConnections(t *testing.T) {
	h := newUsageHarness(t, "")
	stream, done := h.subscription()
	h.send(stream, resetMsg())
	h.send(stream, eventNewMsg(fakeConn{id: "live", user: "alice/mac"}))
	h.send(stream, eventUpdateMsg("live", 1000, 2000))
	h.send(stream, eventNewMsg(fakeConn{id: "short", user: "bob/phone"}))
	h.send(stream, eventClosedMsg(fakeConn{id: "short", user: "bob/phone", up: 10, down: 20, closedAt: 3}))
	h.end(stream, done) // sing-box reloaded: the stream ends without CLOSED for "live"

	h.api.setInstance(2000) // the new instance counts from zero with new connection IDs
	stream, done = h.subscription()
	h.send(stream, resetMsg(fakeConn{id: "next", user: "alice/mac", up: 30, down: 40}))
	h.send(stream, eventUpdateMsg("next", 5, 5))
	h.end(stream, done)

	got := h.totals()
	wantBytes(t, got, "alice/mac", 1035, 2045, 1) // "live" was cut by the reload; its tail is unmeasured
	wantBytes(t, got, "bob/phone", 10, 20, 0)
	if _, _, gap := h.flags(); gap != 0 {
		t.Fatalf("a reload the collector watched is not a gap, got %d", gap)
	}
}

func TestUsageRestartOfTheAgentContinuesWithoutDoubleCounting(t *testing.T) {
	dir := t.TempDir()
	h := newUsageHarness(t, dir)
	stream, done := h.subscription()
	h.send(stream, resetMsg())
	h.send(stream, eventNewMsg(fakeConn{id: "long", user: "alice/mac"}))
	h.send(stream, eventUpdateMsg("long", 100, 100))
	h.c.reportOnce() // persists the counted bytes with the hours they went into, and sends them
	h.end(stream, done)
	if len(h.sent) != 1 || h.sent[0].payload["seq"] != float64(1) {
		t.Fatalf("first report: %+v", h.sent)
	}

	// A new agent process on the same state directory, sing-box kept running the same instance.
	h2 := newUsageHarness(t, dir)
	h2.api.secret = h.c.st.Secret
	stream, done = h2.subscription()
	h2.send(stream, resetMsg(fakeConn{id: "long", user: "alice/mac", up: 130, down: 150},
		fakeConn{id: "while-away", user: "alice/win", up: 9, down: 9, closedAt: 1}))
	h2.end(stream, done)
	got := h2.totals()
	wantBytes(t, got, "alice/mac", 30, 50, 0) // only what was not counted before
	wantBytes(t, got, "alice/win", 9, 9, 0)
	if started, _, gap := h2.flags(); started || gap != 0 {
		t.Fatalf("same instance, nothing lost: started=%v gap=%d", started, gap)
	}
}

func TestUsageInstanceThatEndedUnwatchedIsAGap(t *testing.T) {
	dir := t.TempDir()
	h := newUsageHarness(t, dir)
	stream, done := h.subscription()
	h.send(stream, resetMsg())
	h.send(stream, eventNewMsg(fakeConn{id: "live", user: "alice/mac"}))
	h.c.reportOnce()
	// The agent process dies here (no EOF seen); sing-box is restarted while it is away.
	h.c.mu.Lock()
	h.c.st.Ended = false
	h.c.mu.Unlock()
	h.c.reportOnce()
	_ = done
	close(stream)

	h2 := newUsageHarness(t, dir)
	h2.api.secret = h.c.st.Secret
	h2.advance(10 * time.Minute)
	h2.api.setInstance(5000)
	stream, done = h2.subscription()
	h2.send(stream, resetMsg())
	h2.end(stream, done)
	if _, _, gap := h2.flags(); gap < 600 {
		t.Fatalf("expected the unobserved 10 minutes as a gap, got %d", gap)
	}
	wantBytes(t, h2.totals(), "alice/mac", 0, 0, 1)
}

func TestUsageOverflowOfTheClosedListIsReported(t *testing.T) {
	h := newUsageHarness(t, "")
	stream, done := h.subscription()
	h.send(stream, resetMsg())
	h.end(stream, done)
	var conns []fakeConn
	for i := 0; i < usageClosedRing; i++ {
		conns = append(conns, fakeConn{id: fmt.Sprintf("x%d", i), user: "alice/mac", up: 1, down: 1, closedAt: int64(100 + i)})
	}
	stream, done = h.subscription()
	h.send(stream, resetMsg(conns...))
	h.end(stream, done)
	if _, overflow, _ := h.flags(); !overflow {
		t.Fatal("a full closed list with an unseen oldest entry may hide evicted connections")
	}
	wantBytes(t, h.totals(), "alice/mac", usageClosedRing, usageClosedRing, 0)
}

func TestUsageBatchesAreResentUnchangedUntilAcknowledged(t *testing.T) {
	h := newUsageHarness(t, "")
	stream, done := h.subscription()
	h.send(stream, resetMsg())
	h.send(stream, eventNewMsg(fakeConn{id: "c", user: "alice/mac"}))
	h.send(stream, eventUpdateMsg("c", 10, 20))

	h.answer = 503
	h.c.reportOnce()
	h.send(stream, eventUpdateMsg("c", 1, 1)) // new traffic while the batch is in flight
	h.c.reportOnce()
	if len(h.sent) != 2 {
		t.Fatalf("expected two attempts, got %d", len(h.sent))
	}
	first, retry := h.sent[0].payload, h.sent[1].payload
	if fmt.Sprint(first["seq"], first["hours"]) != fmt.Sprint(retry["seq"], retry["hours"]) {
		t.Fatalf("a retry must resend the same batch:\n%v\n%v", first, retry)
	}

	h.answer = 200
	h.c.reportOnce() // acknowledged
	h.c.reportOnce() // the next batch carries the traffic seen meanwhile
	if len(h.sent) != 4 || h.sent[3].payload["seq"] != float64(2) {
		t.Fatalf("expected batch 2 after the acknowledgement, got %v", h.sent[3].payload["seq"])
	}
	hours := h.sent[3].payload["hours"].([]any)
	devices := hours[0].(map[string]any)["devices"].([]any)
	if d := devices[0].(map[string]any); d["name"] != "alice/mac" || d["up"] != float64(1) || d["down"] != float64(1) {
		t.Fatalf("unexpected second batch: %v", devices)
	}
	h.end(stream, done)

	// A batch the control plane refuses as invalid is dropped so it cannot block later ones.
	h.c.mu.Lock()
	h.c.hour(h.c.now()).bytesOf("alice/mac").Up += 5
	h.c.mu.Unlock()
	h.answer = 400
	h.c.reportOnce()
	h.answer = 200
	h.c.reportOnce()
	if h.sent[len(h.sent)-1].payload["seq"] != nil {
		t.Fatal("after the refused batch only a status report should remain")
	}
}

func TestUsageHoursFollowObservationTime(t *testing.T) {
	h := newUsageHarness(t, "") // the clock starts at 15:59 UTC (23:59 in Singapore)
	stream, done := h.subscription()
	h.send(stream, resetMsg())
	h.send(stream, eventNewMsg(fakeConn{id: "c", user: "alice/mac"}))
	h.send(stream, eventUpdateMsg("c", 100, 100))
	h.advance(2 * time.Minute) // 16:01 UTC: a new day in Asia/Singapore
	h.send(stream, eventUpdateMsg("c", 7, 7))
	h.end(stream, done)
	h.c.mu.Lock()
	defer h.c.mu.Unlock()
	before := h.c.st.Hours[time.Date(2026, 11, 23, 15, 0, 0, 0, time.UTC).Unix()]
	after := h.c.st.Hours[time.Date(2026, 11, 23, 16, 0, 0, 0, time.UTC).Unix()]
	if before == nil || after == nil || before.Devices["alice/mac"].Up != 100 || after.Devices["alice/mac"].Up != 7 {
		t.Fatalf("bytes must land in the hour they were observed: %+v %+v", before, after)
	}
}

func TestUsageInjectionAndUnavailableReasons(t *testing.T) {
	h := newUsageHarness(t, "")
	config := map[string]any{"outbounds": []any{}}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.c.addr = listener.Addr().String() // a free port first
	listener.Close()
	h.c.inject(config)
	services, _ := config["services"].([]any)
	if len(services) != 1 || services[0].(map[string]any)["type"] != "api" || services[0].(map[string]any)["secret"] != h.c.st.Secret {
		t.Fatalf("expected the API service in the candidate: %v", config["services"])
	}

	// The port is held by another program (not answering as this agent's sing-box): no injection.
	other, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	go func() {
		for {
			conn, err := other.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	h.c.addr = other.Addr().String()
	config = map[string]any{}
	h.c.inject(config)
	if _, has := config["services"]; has {
		t.Fatal("must not inject on a port another program uses")
	}
	if state, detail := h.c.status(); state != usageUnavailable || !strings.Contains(detail, "in use") {
		t.Fatalf("got %s %q", state, detail)
	}

	// This agent's own sing-box already serves the API there: injection continues.
	h.c.addr = h.api.addr()
	config = map[string]any{"services": []any{map[string]any{"type": "resolved", "tag": "x"}}}
	h.c.inject(config)
	if services := config["services"].([]any); len(services) != 2 {
		t.Fatalf("expected the existing service kept and ours appended: %v", services)
	}
	if state, _ := h.c.status(); state == usageUnavailable {
		t.Fatal("collection should be possible again")
	}

	config = map[string]any{"services": "nonsense"}
	h.c.inject(config)
	if config["services"] != "nonsense" {
		t.Fatal("a malformed services field is left for sing-box check to judge")
	}
}

func TestUsageOldSingBoxIsReportedUnavailable(t *testing.T) {
	t.Setenv("CCPROXY_FAKE_SINGBOX", "1")
	t.Setenv("CCPROXY_FAKE_NO_API", "1")
	exe, _ := os.Executable()
	supported, ver, detail := probeUsageSupport(exe, t.TempDir(), "127.0.0.1:9096")
	if supported || ver != "1.14.4-fake" || !strings.Contains(detail, "lacks the API service") {
		t.Fatalf("got %v %q %q", supported, ver, detail)
	}
}

func TestUsageWrongSecretIsAnError(t *testing.T) {
	h := newUsageHarness(t, "")
	h.api.secret = "someone-else"
	if err := h.c.subscribeOnce(t.Context()); err == nil || !strings.Contains(err.Error(), "16") {
		t.Fatalf("expected an authentication error, got %v", err)
	}
}

func TestUsageAgentWithoutUsageStillSyncs(t *testing.T) {
	// --usage-api off keeps the agent's config untouched by usage.
	cp := newFakeCP(t)
	a, dir := newTestAgent(t, cp, func(o *Options) { o.UsageAPI = "off"; o.Once = false })
	a.startUsage()
	a.Cycle()
	data, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), usageServiceTag) {
		t.Fatal("--usage-api off must not add the API service")
	}
	if state, detail := a.usage.status(); state != usageUnavailable || !strings.Contains(detail, "off") {
		t.Fatalf("got %s %q", state, detail)
	}
	if cp.last()["apply_state"] != "confirmed" {
		t.Fatalf("sync must not depend on usage: %v", cp.last())
	}
}

func TestUsageAgentInjectsTheServiceAndStillConfirms(t *testing.T) {
	cp := newFakeCP(t)
	usageAddr := freePort(t)
	a, dir := newTestAgent(t, cp, func(o *Options) { o.UsageAPI = usageAddr; o.UsageInterval = 600; o.Once = false })
	a.startUsage()
	a.Cycle()
	var config struct {
		Services []map[string]any `json:"services"`
	}
	data, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	if err := json.Unmarshal(data, &config); err != nil || len(config.Services) != 1 || config.Services[0]["tag"] != usageServiceTag {
		t.Fatalf("expected the API service in the applied config: %s", data)
	}
	if cp.last()["apply_state"] != "confirmed" {
		t.Fatalf("expected a confirmed config with the usage service added: %v", cp.last())
	}
}

// -- credentials ------------------------------------------------------------------------------------------------------

// writeProvenConfig writes a config with VLESS users and the marker and secret the fake Clash API confirms.
func (h *usageHarness) writeProvenConfig(marker string, users map[string]string) {
	var list []any
	for name, uuid := range users {
		list = append(list, map[string]any{"name": name, "uuid": uuid})
	}
	data, _ := json.Marshal(map[string]any{
		"inbounds":     []any{map[string]any{"type": "vless", "tag": "user-x", "users": list}},
		"outbounds":    []any{map[string]any{"type": "direct", "tag": "egress"}, map[string]any{"type": "block", "tag": marker}},
		"experimental": map[string]any{"clash_api": map[string]any{"external_controller": h.api.addr(), "secret": "clash-" + marker}},
	})
	if err := os.WriteFile(h.c.agent.opt.Config, data, 0o600); err != nil {
		h.t.Fatal(err)
	}
	h.api.mu.Lock()
	h.api.clash, h.api.marker = "clash-"+marker, marker
	h.api.mu.Unlock()
	h.c.agent.confirm, h.c.agent.confirmAddress = &http.Client{Timeout: 2 * time.Second}, h.api.addr()
}

const (
	uuidOld = "11111111-1111-4111-8111-111111111111"
	uuidNew = "22222222-2222-4222-8222-222222222222"
)

func TestUsageTagsConnectionsWithTheProvenCredential(t *testing.T) {
	h := newUsageHarness(t, "")
	h.writeProvenConfig("confirm-one", map[string]string{"alice/mac": uuidOld, "bob/phone": "33333333-3333-4333-8333-333333333333"})
	stream, done := h.subscription()
	h.send(stream, resetMsg())
	h.send(stream, eventNewMsg(fakeConn{id: "c1", user: "alice/mac"}))
	h.send(stream, eventClosedMsg(fakeConn{id: "c1", user: "alice/mac", up: 10, down: 20, closedAt: 1}))
	h.end(stream, done)
	h.c.reportOnce()
	hours := h.sent[0].payload["hours"].([]any)
	byName := map[string]map[string]any{}
	for _, d := range hours[0].(map[string]any)["devices"].([]any) {
		d := d.(map[string]any)
		byName[d["name"].(string)] = d
	}
	alice := byName["alice/mac"]
	if alice == nil || alice["credential"] != credentialHash(uuidOld) || alice["up"] != float64(10) || alice["down"] != float64(20) {
		t.Fatalf("expected alice/mac with its credential: %v", byName)
	}
	if bob := byName["bob/phone"]; bob == nil || bob["credential"] == nil || bob["up"] != float64(0) {
		t.Fatalf("a configured device is a measured zero with its credential: %v", byName)
	}
	if strings.Contains(fmt.Sprint(h.sent[0].payload), uuidOld) {
		t.Fatal("the UUID itself must never leave the exit")
	}
}

// alice is deleted and recreated with the same names between two sing-box instances (a reload). The live connection
// from the old instance is cut and stays with the old credential; the new instance's traffic carries the new one.
func TestUsageRecreatedDeviceAcrossAReloadKeepsCredentialsApart(t *testing.T) {
	h := newUsageHarness(t, "")
	h.writeProvenConfig("confirm-one", map[string]string{"alice/mac": uuidOld})
	stream, done := h.subscription()
	h.send(stream, resetMsg())
	h.send(stream, eventNewMsg(fakeConn{id: "live", user: "alice/mac"}))
	h.send(stream, eventUpdateMsg("live", 100, 200))
	h.end(stream, done) // reload

	h.writeProvenConfig("confirm-two", map[string]string{"alice/mac": uuidNew})
	h.api.setInstance(2000)
	stream, done = h.subscription()
	h.send(stream, resetMsg(fakeConn{id: "fresh", user: "alice/mac", up: 5, down: 6}))
	h.end(stream, done)

	got := h.totals()
	wantBytes(t, got, "alice/mac "+credentialHash(uuidOld), 100, 200, 1)
	wantBytes(t, got, "alice/mac "+credentialHash(uuidNew), 5, 6, 0)
	if _, plain := got["alice/mac"]; plain {
		t.Fatalf("no name-only entry expected when the configuration is proven: %v", got)
	}
}

func TestUsageWithoutProofReportsNamesOnly(t *testing.T) {
	h := newUsageHarness(t, "")
	h.writeProvenConfig("confirm-one", map[string]string{"alice/mac": uuidOld})
	h.api.mu.Lock()
	h.api.marker = "confirm-other" // sing-box runs another file (a candidate not reloaded yet)
	h.api.mu.Unlock()
	stream, done := h.subscription()
	h.send(stream, resetMsg())
	h.send(stream, eventNewMsg(fakeConn{id: "c", user: "alice/mac", up: 3, down: 4}))
	h.end(stream, done)
	got := h.totals()
	wantBytes(t, got, "alice/mac", 3, 4, 0)
	if len(got) != 2 { // alice/mac and the unattributed entry
		t.Fatalf("unproven traffic must not carry a credential: %v", got)
	}
}

func TestUsageRestartDuringSubscribeIsRetriedNotApplied(t *testing.T) {
	h := newUsageHarness(t, "")
	h.writeProvenConfig("confirm-one", map[string]string{"alice/mac": uuidOld})
	h.api.mu.Lock()
	h.api.bumpOnce = true
	h.api.mu.Unlock()
	stream := make(chan []byte, 1)
	h.api.streams <- stream
	stream <- resetMsg(fakeConn{id: "c", user: "alice/mac", up: 9, down: 9})
	err := h.c.subscribeOnce(t.Context())
	if err == nil || !strings.Contains(err.Error(), "restarted") {
		t.Fatalf("expected a retry, got %v", err)
	}
	h.c.mu.Lock()
	defer h.c.mu.Unlock()
	if h.c.st.Baselined || len(h.c.st.Conns) != 0 {
		t.Fatal("a snapshot from an instance the mapping was not proven for must not be applied")
	}
}
