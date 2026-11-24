package main

// Per-device traffic collection for the control plane's usage report (POST /agent/usage).
//
// Source. The sing-box API service (a "services" entry of type "api", sing-box 1.14 and later) is part of the
// official release builds, unlike experimental.v2ray_api, which needs a custom build tag. The agent adds a
// loopback API service with its own secret to every candidate config and subscribes to
// daemon.StartedService/SubscribeConnections over gRPC-web (plain HTTP/1.1, so the agent keeps no dependencies).
// Every connection carries the authenticated VLESS user name, which the control plane renders as
// "<user>/<device>". Names alone cannot tell a deleted account from one recreated with the same names, so each
// connection is also tagged with the SHA-256 of its VLESS UUID, taken from --config only when the running sing-box
// proves it serves that file (Clash API marker, checked within one StartedAt instance). Unproved connections are
// reported by name only, and the control plane then refuses to guess between devices with the same names.
//
// Accounting. The agent keeps, per sing-box connection ID, the bytes it has already counted and attributes only
// increases. NEW and CLOSED events carry a connection's running totals, UPDATE events carry deltas, and every
// subscription starts with a reset snapshot of all open connections plus the last 1000 closed ones with their
// final totals. A connection that opens and closes between updates is therefore still counted in full, and a
// dropped event or a resubscription is repaired from the snapshot. Bytes are attributed to the UTC hour in which
// the agent observes them; the stream delivers updates every usageUpdateInterval.
//
// Known limits are reported, never hidden, as flags on the hour in which they are detected:
//   - cut: a live connection disappeared without final totals (sing-box reloaded or restarted). Its last
//     usageUpdateInterval of traffic is not measured.
//   - overflow: more than 1000 connections closed while the agent was not subscribed, so some final totals may
//     have been evicted from sing-box before the agent read them.
//   - gap: a sing-box instance ended while the agent was not watching (for example the agent was stopped), so its
//     final traffic is unknown. gap_seconds is the unobserved time.
//   - started: collection began during this hour (the first subscription ever, or after the state was lost).
//     Traffic before that point is not counted.
//
// Delivery. Hours are sent in batches numbered by a per-collector sequence. A batch is written to the state file
// before it is sent and is resent unchanged until the control plane acknowledges it, which deduplicates by
// (host, collector, seq). Collection runs in its own goroutines: configuration sync and the heartbeat never wait
// for it, and its failures only change the collector state it reports.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	usageServiceTag     = "ccproxy-usage"
	usageStateFile      = "usage-state.json"
	usageClosedRing     = 1000 // sing-box keeps this many closed connections (common/trafficcontrol)
	usageUpdateInterval = 250 * time.Millisecond
	usageResubscribe    = 5 * time.Minute // reconcile against a fresh snapshot and prune closed connections
	usageMaxHours       = 24 * 30         // unsent hours kept while the control plane is unreachable
	usageBatchHours     = 48              // hours per report, which keeps a report well below the 1 MiB body limit
	usageFrameMax       = 64 << 20
	usageGapGrace       = 5 * time.Second // reconnect time that does not count as unobserved

	usageCollecting  = "collecting"
	usageUnavailable = "unavailable"
	usageError       = "error"
	usageStarting    = "starting"

	eventNew    = 0
	eventUpdate = 1
	eventClosed = 2
)

type usageBytes struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
	Cut  int64 `json:"cut,omitempty"` // connections that ended without final totals
}

// usageHour is one UTC hour of observations. Devices maps a sing-box user name to its bytes; a device listed
// with zero bytes was configured and measured, which the report shows as a measured zero.
type usageHour struct {
	Hour         int64                  `json:"hour"`
	Started      bool                   `json:"started,omitempty"`
	Overflow     bool                   `json:"overflow,omitempty"`
	GapSeconds   int64                  `json:"gap_seconds,omitempty"`
	Unattributed usageBytes             `json:"unattributed"`
	Devices      map[string]*usageBytes `json:"devices"`
}

type usageBatch struct {
	Seq   int64        `json:"seq"`
	Hours []*usageHour `json:"hours"`
}

// usageConn is what has been counted for one sing-box connection. K is the credential (hex SHA-256 of the VLESS
// UUID) its user name had in the configuration the connection's sing-box instance proved it runs, or "".
type usageConn struct {
	User   string `json:"u"`
	K      string `json:"k,omitempty"`
	Up     int64  `json:"up"`
	Down   int64  `json:"down"`
	Closed bool   `json:"c,omitempty"`
}

// usageState is persisted in --state-dir. Counted bytes and the hours they went into are saved together, so a
// restart neither loses nor repeats them.
type usageState struct {
	Collector string                `json:"collector"`
	Secret    string                `json:"secret"`
	NextSeq   int64                 `json:"next_seq"`
	Baselined bool                  `json:"baselined"`
	Instance  int64                 `json:"instance"`       // StartedAt (ms) of the sing-box instance last subscribed to
	Ended     bool                  `json:"instance_ended"` // that instance's stream ended (the instance stopped)
	LastSeen  int64                 `json:"last_seen"`      // unix seconds the agent last saw that instance's stream
	Conns     map[string]*usageConn `json:"conns"`
	Hours     map[int64]*usageHour  `json:"hours"`
	Batch     *usageBatch           `json:"batch,omitempty"`
}

type connInfo struct {
	eventType          int64
	id                 string
	user               string
	up, down           int64 // totals, when the event carries the connection
	closedAt           int64
	hasConnection      bool
	upDelta, downDelta int64 // UPDATE events
}

type usageCollector struct {
	agent   *Agent
	addr    string // host:port of the loopback API service
	path    string
	api     *http.Client // unary calls
	stream  *http.Client // the subscription (no overall timeout)
	now     func() time.Time
	sendFn  func(payload map[string]any) (int, error)
	singbox string
	running sync.WaitGroup // the follow and report goroutines

	mu          sync.Mutex
	st          usageState
	supported   bool
	disabled    string // why collection is unavailable ("" when it is possible)
	injected    bool   // the API service is in the candidate configs this process writes
	subscribed  bool
	lastErr     string
	errSince    time.Time
	notAccepted bool              // the control plane answered 404: it predates usage reports
	mapping     map[string]string // VLESS user name -> credential, for the subscribed instance; nil when unproved
	usersCache  struct {
		mod   time.Time
		size  int64
		names []string
	}
}

// newUsageCollector prepares collection for --usage-api ADDR ("off" disables it). Collection stays unavailable,
// with the reason reported to the control plane, when sing-box lacks the API service.
func newUsageCollector(a *Agent) (*usageCollector, error) {
	c := &usageCollector{
		agent: a, path: filepath.Join(a.opt.StateDir, usageStateFile), now: time.Now,
		api: &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		stream: &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, ResponseHeaderTimeout: 10 * time.Second},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
	c.sendFn = c.post
	if strings.EqualFold(a.opt.UsageAPI, "off") {
		c.disabled = "disabled with --usage-api off"
	} else {
		addr, err := loopbackAPI(a.opt.UsageAPI)
		if err != nil {
			return nil, errors.New(strings.Replace(err.Error(), "--confirm-api", "--usage-api", 1))
		}
		if addr == a.confirmAddress {
			return nil, errors.New("--usage-api must differ from --confirm-api")
		}
		c.addr = addr
	}
	if err := c.load(); err != nil {
		return nil, err
	}
	if c.disabled == "" {
		c.supported, c.singbox, c.disabled = probeUsageSupport(a.opt.SingBox, a.opt.StateDir, c.addr)
	}
	return c, nil
}

func (c *usageCollector) load() error {
	data, err := os.ReadFile(c.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		c.st = usageState{}
	case err != nil:
		return fmt.Errorf("usage state: %w", err)
	default:
		if err := json.Unmarshal(data, &c.st); err != nil {
			c.agent.logf("usage state %s is unreadable (%v); starting a new collector", c.path, err)
			c.st = usageState{}
		}
	}
	if c.st.Collector == "" || c.st.Secret == "" {
		c.st = usageState{Collector: randomHex(), Secret: randomHex(), NextSeq: 1}
	}
	if c.st.Conns == nil {
		c.st.Conns = map[string]*usageConn{}
	}
	if c.st.Hours == nil {
		c.st.Hours = map[int64]*usageHour{}
	}
	return nil
}

// save writes the state atomically (0600: the file holds the API secret).
func (c *usageCollector) save() error {
	data, err := json.Marshal(&c.st)
	if err != nil {
		return err
	}
	tmp, err := writeTemp(filepath.Dir(c.path), data)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, c.path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// probeUsageSupport asks `sing-box check` whether this build accepts the API service.
func probeUsageSupport(singbox, dir, addr string) (bool, string, string) {
	versionText := ""
	if out, err := exec.Command(singbox, "version").Output(); err == nil {
		line, _, _ := strings.Cut(string(out), "\n")
		versionText = strings.TrimSpace(strings.TrimPrefix(line, "sing-box version "))
	}
	host, port, _ := net.SplitHostPort(addr)
	portNumber, _ := strconv.Atoi(port)
	probe, _ := json.Marshal(map[string]any{
		"log":      map[string]any{"level": "error"},
		"services": []any{map[string]any{"type": "api", "tag": usageServiceTag, "listen": host, "listen_port": portNumber, "secret": "probe"}},
	})
	tmp, err := writeTemp(dir, probe)
	if err != nil {
		return false, versionText, "cannot write a probe config: " + err.Error()
	}
	defer os.Remove(tmp)
	var stderr bytes.Buffer
	check := exec.Command(singbox, "check", "-c", tmp)
	check.Stderr = &stderr
	if err := check.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		return false, versionText, "sing-box " + versionText + " lacks the API service (sing-box 1.14 or later is required): " + truncateText(detail, 300)
	}
	return true, versionText, ""
}

func truncateText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// inject adds the API service to a candidate config. It never fails the candidate: when the service cannot be
// added (the loopback port belongs to another program, or 'services' is not a list) collection is reported as
// unavailable and the configuration is applied without it.
func (c *usageCollector) inject(config map[string]any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.injected = false
	if !c.supported {
		return
	}
	services, isList := config["services"].([]any)
	if raw, present := config["services"]; present && raw != nil && !isList {
		c.disabled = "the server config's 'services' is not a list"
		return
	}
	if !c.portUsable() {
		c.disabled = "the usage API address " + c.addr + " is in use by another program; pass a free --usage-api"
		c.agent.logf("usage collection unavailable: %s", c.disabled)
		return
	}
	host, port, _ := net.SplitHostPort(c.addr)
	portNumber, _ := strconv.Atoi(port)
	config["services"] = append(services, map[string]any{
		"type": "api", "tag": usageServiceTag, "listen": host, "listen_port": portNumber, "secret": c.st.Secret,
	})
	c.injected, c.disabled = true, ""
}

// portUsable: the port is free, or this agent's sing-box already serves the API there with our secret.
func (c *usageCollector) portUsable() bool {
	if l, err := net.Listen("tcp", c.addr); err == nil {
		l.Close()
		return true
	}
	_, err := c.startedAt()
	return err == nil
}

// -- gRPC-web ------------------------------------------------------------------------------------------------

func grpcFrame(message []byte) []byte {
	frame := make([]byte, 5+len(message))
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(message)))
	copy(frame[5:], message)
	return frame
}

func (c *usageCollector) request(ctx context.Context, method string, message []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", "http://"+c.addr+"/daemon.StartedService/"+method, bytes.NewReader(grpcFrame(message)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/grpc-web+proto")
	req.Header.Set("X-Grpc-Web", "1")
	req.Header.Set("Authorization", "Bearer "+c.st.Secret)
	return req, nil
}

// grpcStatus reads a status from response headers (trailers-only answers) or a trailer frame.
func grpcStatus(text string) (int, string) {
	code, message := -1, ""
	for _, line := range strings.Split(text, "\r\n") {
		key, value, _ := strings.Cut(line, ":")
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "grpc-status":
			code, _ = strconv.Atoi(strings.TrimSpace(value))
		case "grpc-message":
			message = strings.TrimSpace(value)
		}
	}
	return code, message
}

func checkGRPCResponse(resp *http.Response) error {
	if resp.StatusCode != 200 {
		return fmt.Errorf("API service answered HTTP %d", resp.StatusCode)
	}
	if code := resp.Header.Get("Grpc-Status"); code != "" && code != "0" {
		return fmt.Errorf("API service error %s: %s", code, resp.Header.Get("Grpc-Message"))
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/grpc-web") {
		return fmt.Errorf("not a sing-box API service (content type %q)", resp.Header.Get("Content-Type"))
	}
	return nil
}

func readGRPCFrame(r io.Reader) (byte, []byte, error) {
	var head [5]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(head[1:])
	if n > usageFrameMax {
		return 0, nil, fmt.Errorf("API frame of %d bytes exceeds the limit", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return head[0], payload, nil
}

// startedAt identifies the running sing-box instance (GetStartedAt, milliseconds).
func (c *usageCollector) startedAt() (int64, error) {
	if c.addr == "" {
		return 0, errors.New("usage API disabled")
	}
	req, err := c.request(context.Background(), "GetStartedAt", nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.api.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if err := checkGRPCResponse(resp); err != nil {
		return 0, err
	}
	var value int64
	got := false
	for {
		flag, payload, err := readGRPCFrame(resp.Body)
		if err != nil {
			if got && errors.Is(err, io.EOF) {
				return value, nil
			}
			return 0, err
		}
		if flag&0x80 != 0 {
			if code, message := grpcStatus(string(payload)); code != 0 {
				return 0, fmt.Errorf("API service error %d: %s", code, message)
			}
			if !got {
				return 0, errors.New("API service sent no StartedAt")
			}
			return value, nil
		}
		fieldsOf, err := pbFields(payload)
		if err != nil {
			return 0, err
		}
		got = true
		for _, f := range fieldsOf {
			if f.num == 1 && f.wire == 0 {
				value = int64(f.varint)
			}
		}
	}
}

// -- protobuf (the few messages used) -------------------------------------------------------------------------

type pbField struct {
	num    int
	wire   int
	varint uint64
	bytes  []byte
}

func pbVarint(b []byte) (uint64, int, error) {
	var v uint64
	for i := 0; i < len(b) && i < 10; i++ {
		v |= uint64(b[i]&0x7f) << (7 * i)
		if b[i] < 0x80 {
			return v, i + 1, nil
		}
	}
	return 0, 0, errors.New("malformed protobuf varint")
}

func pbFields(b []byte) ([]pbField, error) {
	var out []pbField
	for len(b) > 0 {
		key, n, err := pbVarint(b)
		if err != nil {
			return nil, err
		}
		b = b[n:]
		f := pbField{num: int(key >> 3), wire: int(key & 7)}
		switch f.wire {
		case 0:
			if f.varint, n, err = pbVarint(b); err != nil {
				return nil, err
			}
			b = b[n:]
		case 1:
			if len(b) < 8 {
				return nil, errors.New("truncated protobuf field")
			}
			b = b[8:]
		case 2:
			size, n, err := pbVarint(b)
			if err != nil || uint64(len(b)-n) < size {
				return nil, errors.New("truncated protobuf field")
			}
			f.bytes, b = b[n:n+int(size)], b[n+int(size):]
		case 5:
			if len(b) < 4 {
				return nil, errors.New("truncated protobuf field")
			}
			b = b[4:]
		default:
			return nil, fmt.Errorf("unsupported protobuf wire type %d", f.wire)
		}
		out = append(out, f)
	}
	return out, nil
}

// decodeConnectionEvents parses daemon.ConnectionEvents.
func decodeConnectionEvents(payload []byte) ([]connInfo, bool, error) {
	top, err := pbFields(payload)
	if err != nil {
		return nil, false, err
	}
	var events []connInfo
	reset := false
	for _, f := range top {
		switch {
		case f.num == 2 && f.wire == 0:
			reset = f.varint != 0
		case f.num == 1 && f.wire == 2:
			event, err := pbFields(f.bytes)
			if err != nil {
				return nil, false, err
			}
			var e connInfo
			for _, ef := range event {
				switch {
				case ef.num == 1 && ef.wire == 0:
					e.eventType = int64(ef.varint)
				case ef.num == 2 && ef.wire == 2:
					e.id = string(ef.bytes)
				case ef.num == 4 && ef.wire == 0:
					e.upDelta = int64(ef.varint)
				case ef.num == 5 && ef.wire == 0:
					e.downDelta = int64(ef.varint)
				case ef.num == 6 && ef.wire == 0 && e.closedAt == 0:
					e.closedAt = int64(ef.varint)
				case ef.num == 3 && ef.wire == 2:
					conn, err := pbFields(ef.bytes)
					if err != nil {
						return nil, false, err
					}
					e.hasConnection = true
					for _, cf := range conn {
						switch {
						case cf.num == 1 && cf.wire == 2 && e.id == "":
							e.id = string(cf.bytes)
						case cf.num == 10 && cf.wire == 2:
							e.user = string(cf.bytes)
						case cf.num == 13 && cf.wire == 0 && cf.varint != 0:
							e.closedAt = int64(cf.varint)
						case cf.num == 16 && cf.wire == 0:
							e.up = int64(cf.varint)
						case cf.num == 17 && cf.wire == 0:
							e.down = int64(cf.varint)
						}
					}
				}
			}
			events = append(events, e)
		}
	}
	return events, reset, nil
}

// -- accounting ------------------------------------------------------------------------------------------------

func (c *usageCollector) hour(t time.Time) *usageHour {
	key := t.Unix() - t.Unix()%3600
	h := c.st.Hours[key]
	if h == nil {
		h = &usageHour{Hour: key, Devices: map[string]*usageBytes{}}
		c.st.Hours[key] = h
	}
	return h
}

// bytesOf returns the counters for a device key: "<VLESS user name> <credential>" or, without a credential, the
// name alone (names contain no spaces). "" is traffic without a user.
func (h *usageHour) bytesOf(key string) *usageBytes {
	if key == "" {
		return &h.Unattributed
	}
	b := h.Devices[key]
	if b == nil {
		b = &usageBytes{}
		h.Devices[key] = b
	}
	return b
}

func deviceKey(user, credential string) string {
	if user == "" || credential == "" {
		return user
	}
	return user + " " + credential
}

func (conn *usageConn) key() string { return deviceKey(conn.User, conn.K) }

// credentialHash matches the control plane: hex SHA-256 of the UUID in lowercase canonical text.
func credentialHash(uuid string) string {
	digest := sha256.Sum256([]byte(strings.ToLower(uuid)))
	return hex.EncodeToString(digest[:])
}

// observe moves a connection's counted bytes up to the totals sing-box reports and attributes the increase.
func (c *usageCollector) observe(h *usageHour, id, user string, up, down int64, closed bool) {
	conn := c.st.Conns[id]
	if conn == nil {
		conn = &usageConn{User: user}
		c.st.Conns[id] = conn
	}
	if user != "" {
		conn.User = user
	}
	if conn.K == "" && conn.User != "" {
		conn.K = c.mapping[conn.User] // a connection belongs to the instance it was first seen on
	}
	du, dd := max(up-conn.Up, 0), max(down-conn.Down, 0)
	conn.Up, conn.Down = max(conn.Up, up), max(conn.Down, down)
	conn.Closed = conn.Closed || closed
	if du != 0 || dd != 0 {
		b := h.bytesOf(conn.key())
		b.Up += du
		b.Down += dd
	}
}

// applyReset reconciles against a subscription's initial snapshot: every open connection and the closed ones
// sing-box still remembers, each with its totals.
func (c *usageCollector) applyReset(events []connInfo, instance int64) {
	now := c.now()
	h := c.hour(now)
	if c.st.Instance != 0 && instance != c.st.Instance && !c.st.Ended {
		// The previous instance stopped while nobody watched: its last traffic is unknown.
		gap := now.Unix() - c.st.LastSeen
		if c.st.LastSeen == 0 || gap < 0 {
			gap = 0
		}
		h.GapSeconds += max(gap, 1)
		c.agent.logf("usage: sing-box instance changed while the collector was away (%ds unobserved)", gap)
	}
	if !c.st.Baselined {
		// History starts now: what sing-box counted before is not ours to report.
		for _, e := range events {
			if e.hasConnection && e.id != "" {
				c.st.Conns[e.id] = &usageConn{User: e.user, K: c.mapping[e.user], Up: e.up, Down: e.down, Closed: e.closedAt != 0}
			}
		}
		c.st.Baselined, h.Started = true, true
	} else {
		seen := make(map[string]bool, len(events))
		closedCount, oldestAt, oldestKnown := 0, int64(0), true
		for _, e := range events {
			if !e.hasConnection || e.id == "" {
				continue
			}
			seen[e.id] = true
			if e.closedAt != 0 {
				closedCount++
				if oldestAt == 0 || e.closedAt < oldestAt {
					oldestAt, oldestKnown = e.closedAt, c.st.Conns[e.id] != nil
				}
			}
			c.observe(h, e.id, e.user, e.up, e.down, e.closedAt != 0)
		}
		for id, conn := range c.st.Conns {
			if seen[id] {
				continue
			}
			if !conn.Closed {
				h.bytesOf(conn.key()).Cut++
			}
			delete(c.st.Conns, id)
		}
		if closedCount >= usageClosedRing && !oldestKnown {
			h.Overflow = true
		}
	}
	c.st.Instance, c.st.Ended, c.st.LastSeen = instance, false, now.Unix()
	c.touchConfigured(h)
}

func (c *usageCollector) applyEvents(events []connInfo) {
	now := c.now()
	h := c.hour(now)
	for _, e := range events {
		switch e.eventType {
		case eventNew, eventClosed:
			// A CLOSED event without the connection is repaired from the next snapshot's closed list.
			if e.hasConnection && e.id != "" {
				c.observe(h, e.id, e.user, e.up, e.down, e.eventType == eventClosed || e.closedAt != 0)
			}
		case eventUpdate:
			if conn := c.st.Conns[e.id]; conn != nil && !conn.Closed && (e.upDelta > 0 || e.downDelta > 0) {
				conn.Up += max(e.upDelta, 0)
				conn.Down += max(e.downDelta, 0)
				b := h.bytesOf(conn.key())
				b.Up += max(e.upDelta, 0)
				b.Down += max(e.downDelta, 0)
			}
		}
	}
	c.st.LastSeen = now.Unix()
}

// configuredUsers lists the VLESS user names in --config: the devices this host measures, traffic or not.
func (c *usageCollector) configuredUsers() []string {
	st, err := os.Stat(c.agent.opt.Config)
	if err != nil {
		return nil
	}
	if st.ModTime().Equal(c.usersCache.mod) && st.Size() == c.usersCache.size {
		return c.usersCache.names
	}
	data, err := os.ReadFile(c.agent.opt.Config)
	if err != nil {
		return nil
	}
	var config struct {
		Inbounds []struct {
			Type  string `json:"type"`
			Users []struct {
				Name string `json:"name"`
			} `json:"users"`
		} `json:"inbounds"`
	}
	if json.Unmarshal(data, &config) != nil {
		return nil
	}
	var names []string
	for _, in := range config.Inbounds {
		if in.Type != "vless" {
			continue
		}
		for _, u := range in.Users {
			if u.Name != "" {
				names = append(names, u.Name)
			}
		}
	}
	c.usersCache.mod, c.usersCache.size, c.usersCache.names = st.ModTime(), st.Size(), names
	return names
}

func (c *usageCollector) touchConfigured(h *usageHour) {
	if c.mapping != nil { // the running instance's devices, with their credentials
		for name, credential := range c.mapping {
			h.bytesOf(deviceKey(name, credential))
		}
		return
	}
	for _, name := range c.configuredUsers() {
		h.bytesOf(name)
	}
}

// provenMapping reads --config and returns its VLESS user names with their credentials, but only when the running
// sing-box proves it serves exactly that file: its Clash API, asked with the file's secret, lists the file's
// confirmation marker (the same evidence the agent uses to confirm a reload). Otherwise nil: usage is then reported
// by name only, and the control plane never guesses between two devices with the same names.
func (c *usageCollector) provenMapping() map[string]string {
	if c.agent.confirm == nil || c.agent.confirmAddress == "" {
		return nil
	}
	data, err := os.ReadFile(c.agent.opt.Config)
	if err != nil {
		return nil
	}
	var config struct {
		Inbounds []struct {
			Type  string `json:"type"`
			Users []struct {
				Name string `json:"name"`
				UUID string `json:"uuid"`
			} `json:"users"`
		} `json:"inbounds"`
		Outbounds []struct {
			Tag string `json:"tag"`
		} `json:"outbounds"`
		Experimental struct {
			ClashAPI struct {
				Secret string `json:"secret"`
			} `json:"clash_api"`
		} `json:"experimental"`
	}
	if json.Unmarshal(data, &config) != nil || config.Experimental.ClashAPI.Secret == "" {
		return nil
	}
	var markers []string
	for _, o := range config.Outbounds {
		if strings.HasPrefix(o.Tag, markerPrefix) {
			markers = append(markers, o.Tag)
		}
	}
	if len(markers) != 1 {
		return nil
	}
	req, err := http.NewRequest("GET", "http://"+c.agent.confirmAddress+"/proxies", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+config.Experimental.ClashAPI.Secret)
	resp, err := c.agent.confirm.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var answer struct {
		Proxies map[string]json.RawMessage `json:"proxies"`
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, confirmMaxBytes))
	if err != nil || resp.StatusCode != 200 || json.Unmarshal(body, &answer) != nil {
		return nil
	}
	if _, loaded := answer.Proxies[markers[0]]; !loaded {
		return nil
	}
	mapping := map[string]string{}
	for _, in := range config.Inbounds {
		if in.Type != "vless" {
			continue
		}
		for _, u := range in.Users {
			if u.Name != "" && u.UUID != "" {
				mapping[u.Name] = credentialHash(u.UUID)
			}
		}
	}
	return mapping
}

// -- subscription loop --------------------------------------------------------------------------------------

// subscribeOnce follows one subscription until it ends. It returns nil when it ended on its own schedule.
func (c *usageCollector) subscribeOnce(ctx context.Context) error {
	instance, err := c.startedAt()
	if err != nil {
		return err
	}
	// Asked after StartedAt and checked against it again once the snapshot arrived, so the mapping, the snapshot
	// and the stream all belong to one sing-box instance.
	mapping := c.provenMapping()
	ctx, cancel := context.WithTimeout(ctx, usageResubscribe)
	defer cancel()
	var interval []byte
	interval = binary.AppendUvarint(append(interval, 0x08), uint64(usageUpdateInterval))
	req, err := c.request(ctx, "SubscribeConnections", interval)
	if err != nil {
		return err
	}
	resp, err := c.stream.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := checkGRPCResponse(resp); err != nil {
		return err
	}
	reader := bufio.NewReaderSize(resp.Body, 64<<10)
	first := true
	defer func() { c.mu.Lock(); c.subscribed = false; c.mu.Unlock() }()
	for {
		flag, payload, err := readGRPCFrame(reader)
		if err != nil {
			if ctx.Err() != nil {
				return nil // our own resubscription deadline (or shutdown)
			}
			c.mu.Lock()
			if !first && c.st.Instance == instance {
				c.st.Ended = true // the stream ends when the instance stops (reload, restart, exit)
				c.st.LastSeen = c.now().Unix()
			}
			c.mu.Unlock()
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		if flag&0x80 != 0 {
			code, message := grpcStatus(string(payload))
			c.mu.Lock()
			if !first && c.st.Instance == instance {
				c.st.Ended, c.st.LastSeen = true, c.now().Unix()
			}
			c.mu.Unlock()
			if code > 0 {
				return fmt.Errorf("API service error %d: %s", code, message)
			}
			return nil
		}
		events, reset, err := decodeConnectionEvents(payload)
		if err != nil {
			return err
		}
		if first {
			if again, err := c.startedAt(); err != nil || again != instance {
				return errors.New("sing-box restarted while the collector subscribed; subscribing again")
			}
		}
		c.mu.Lock()
		if first {
			c.mapping = mapping
		}
		if first || reset {
			c.applyReset(events, instance)
			c.subscribed, c.lastErr, c.errSince = true, "", time.Time{}
		} else {
			c.applyEvents(events)
		}
		c.mu.Unlock()
		first = false
	}
}

func (c *usageCollector) followLoop(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		c.mu.Lock()
		ready := c.injected && c.disabled == ""
		c.mu.Unlock()
		if !ready {
			sleepCtx(ctx, time.Second)
			continue
		}
		err := c.subscribeOnce(ctx)
		c.mu.Lock()
		c.subscribed = false
		if err != nil {
			if c.lastErr == "" {
				c.errSince = c.now()
			}
			c.lastErr = err.Error()
		}
		c.mu.Unlock()
		if err == nil {
			backoff = time.Second
			continue
		}
		sleepCtx(ctx, backoff)
		backoff = min(backoff*2, 10*time.Second)
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// -- reporting ----------------------------------------------------------------------------------------------

// status is what the console shows for this exit's collector.
func (c *usageCollector) status() (string, string) {
	switch {
	case c.disabled != "":
		return usageUnavailable, c.disabled
	case !c.supported:
		return usageUnavailable, "sing-box lacks the API service"
	case c.subscribed:
		return usageCollecting, ""
	case c.lastErr != "" && c.now().Sub(c.errSince) > 30*time.Second:
		return usageError, "cannot read connections from sing-box: " + c.lastErr
	default:
		return usageStarting, "waiting for sing-box to load the usage API"
	}
}

// cutBatch moves the oldest unsent hours into a numbered batch unless one is still unacknowledged.
func (c *usageCollector) cutBatch() {
	if c.subscribed {
		c.touchConfigured(c.hour(c.now()))
		c.st.LastSeen = c.now().Unix() // a quiet stream sends nothing, but the instance is still watched
	}
	keys := make([]int64, 0, len(c.st.Hours))
	for k := range c.st.Hours {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for len(keys) > usageMaxHours { // the control plane has been away for too long: keep the newest hours
		delete(c.st.Hours, keys[0])
		keys = keys[1:]
		c.st.Hours[keys[0]].GapSeconds += 3600
	}
	if c.st.Batch != nil || len(keys) == 0 {
		return
	}
	keys = keys[:min(len(keys), usageBatchHours)]
	batch := &usageBatch{Seq: c.st.NextSeq}
	for _, k := range keys {
		batch.Hours = append(batch.Hours, c.st.Hours[k])
		delete(c.st.Hours, k)
	}
	c.st.Batch = batch
	c.st.NextSeq++
}

func hourPayload(h *usageHour) map[string]any {
	names := make([]string, 0, len(h.Devices))
	for name := range h.Devices {
		names = append(names, name)
	}
	sort.Strings(names)
	devices := make([]any, 0, len(names))
	for _, name := range names {
		b := h.Devices[name]
		entry := map[string]any{"name": name, "up": b.Up, "down": b.Down, "cut": b.Cut}
		if user, credential, found := strings.Cut(name, " "); found {
			entry["name"], entry["credential"] = user, credential
		}
		devices = append(devices, entry)
	}
	return map[string]any{
		"hour": h.Hour, "started": h.Started, "overflow": h.Overflow, "gap_seconds": h.GapSeconds,
		"unattributed": map[string]any{"up": h.Unattributed.Up, "down": h.Unattributed.Down, "cut": h.Unattributed.Cut},
		"devices":      devices,
	}
}

// reportOnce persists the state, then sends the pending batch (or a status-only report).
func (c *usageCollector) reportOnce() {
	c.mu.Lock()
	c.cutBatch()
	if err := c.save(); err != nil {
		c.mu.Unlock()
		c.agent.logf("usage: cannot save %s, not reporting: %v", c.path, err)
		return
	}
	state, detail := c.status()
	payload := map[string]any{
		"collector": c.st.Collector, "agent_version": version, "singbox_version": c.singbox,
		"state": state, "detail": detail, "seq": nil, "hours": []any{},
	}
	batch := c.st.Batch
	if batch != nil {
		hours := make([]any, 0, len(batch.Hours))
		for _, h := range batch.Hours {
			hours = append(hours, hourPayload(h))
		}
		payload["seq"], payload["hours"] = batch.Seq, hours
	}
	c.mu.Unlock()

	status, err := c.sendFn(payload)
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case err == nil && status == 200:
		c.notAccepted = false
		if batch != nil && c.st.Batch == batch {
			c.st.Batch = nil
			if err := c.save(); err != nil {
				c.agent.logf("usage: cannot save %s: %v", c.path, err)
			}
		}
	case status == 404:
		if !c.notAccepted {
			c.agent.logf("usage: the control plane does not accept usage reports yet; keeping them")
		}
		c.notAccepted = true
	case status == 400 || status == 409 || status == 413 || status == 422:
		// The control plane will never accept this batch; keeping it would block every later one.
		c.agent.logf("usage: batch %d refused with HTTP %d, dropping it: %v", batch.seqOrZero(), status, err)
		c.st.Batch = nil
		if err := c.save(); err != nil {
			c.agent.logf("usage: cannot save %s: %v", c.path, err)
		}
	default:
		c.agent.logf("usage report failed, will retry: %v", err)
	}
}

func (b *usageBatch) seqOrZero() int64 {
	if b == nil {
		return 0
	}
	return b.Seq
}

func (c *usageCollector) post(payload map[string]any) (int, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequest("POST", c.agent.opt.CP+"/agent/usage", bytes.NewReader(data))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.agent.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.agent.cp.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != 200 {
		return resp.StatusCode, fmt.Errorf("POST /agent/usage: HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return 200, nil
}

func (c *usageCollector) reportLoop(ctx context.Context) {
	interval := time.Duration(c.agent.opt.UsageInterval * float64(time.Second))
	for {
		c.reportOnce()
		select {
		case <-ctx.Done():
			c.reportOnce()
			return
		case <-time.After(interval):
		}
	}
}

// Start runs collection and reporting in the background until ctx ends. Wait returns once both have stopped,
// after the final report.
func (c *usageCollector) Start(ctx context.Context) {
	c.running.Add(2)
	go func() { defer c.running.Done(); c.followLoop(ctx) }()
	go func() { defer c.running.Done(); c.reportLoop(ctx) }()
}

func (c *usageCollector) Wait() { c.running.Wait() }
