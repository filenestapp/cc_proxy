package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
)

const (
	probeRetention = 7 * 86400
	probeHistory   = 20
	maxResults     = 2000
)

type probeEntry struct {
	Name string `json:"name"`
	Host string `json:"host"`
	Port int    `json:"port"`
	Kind string `json:"kind"`
}

type monitorSettings struct {
	Targets []string     `json:"egress_targets"`
	Entries []probeEntry `json:"entries"`
}

func listEntries(ctx context.Context, db database, monitor monitorSettings) ([]probeEntry, error) {
	out, err := rowsOf[probeEntry](ctx, db, `SELECT h.name, `+publicEntryHostSQL+` AS host, min(u.port) AS port, 'host' AS kind
		FROM hosts h JOIN users u ON u.host = h.name
		WHERE h.public_host <> '' OR h.observed_public_ipv4 IS NOT NULL GROUP BY h.name ORDER BY h.name`)
	if err != nil {
		return nil, err
	}
	for _, e := range monitor.Entries {
		e.Kind = "extra"
		out = append(out, e)
	}
	return out, nil
}

type probeInput struct {
	Subject   *string  `json:"subject"`
	Target    *string  `json:"target"`
	OK        *bool    `json:"ok"`
	LatencyMS *float64 `json:"latency_ms"`
	Detail    string   `json:"detail"`
}

type heartbeat struct {
	ConfigETag      string  `json:"config_etag"`
	AgentVersion    string  `json:"agent_version"`
	SingboxRunning  *bool   `json:"singbox_running"`
	ApplyError      *string `json:"apply_error"`
	ApplyState      string  `json:"apply_state"`
	LocalEgressIPv4 string  `json:"local_egress_ipv4"`
	// Sent by agents with XTCP sync (xtcp_sync.go); absent from older agents.
	XTCP *xtcpReport `json:"xtcp"`
	// The managed-update outcome (agent_update.go); absent from older agents.
	Update *agentUpdateReport `json:"update"`
}

// IsGlobalUnicast also includes locally scoped and special-purpose IPv4 ranges.
var nonPublicIPv4Blocks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

func isPublicIPv4(addr netip.Addr) bool {
	if !addr.Is4() || !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}
	for _, block := range nonPublicIPv4Blocks {
		if block.Contains(addr) {
			return false
		}
	}
	return true
}

func (s *store) reportAgent(ctx context.Context, name, token string, address netip.Addr, hb heartbeat, probes []probeInput) error {
	localAddress, _ := netip.ParseAddr(hb.LocalEgressIPv4)
	canSeedPool := localAddress.Is4() && localAddress.IsGlobalUnicast()
	save := func(tx pgx.Tx) error {
		var agent string
		tokenHash := hashToken(token)
		err := tx.QueryRow(ctx, "SELECT name FROM hosts WHERE name = $1 AND agent_token_hash = $2 FOR KEY SHARE",
			name, tokenHash).Scan(&agent)
		if errors.Is(err, pgx.ErrNoRows) {
			return failure(401, "unauthorized")
		}
		if err != nil {
			return err
		}
		ips, err := columnOf[string](ctx, tx, "SELECT host(ip) FROM egress_ips WHERE host = $1", name)
		if err != nil {
			return err
		}
		own := make(map[string]bool, len(ips))
		for _, ip := range ips {
			own[ip] = true
		}
		for _, p := range probes {
			if p.Subject == nil || !own[*p.Subject] {
				return failure(400, "probes must be results for this host's egress IPs")
			}
		}
		if err := s.recordProbes(ctx, tx, "egress", name, probes); err != nil {
			return err
		}
		applied := ""
		if hb.ApplyError != nil {
			applied = truncate(*hb.ApplyError, 300)
		}
		var state *string
		switch hb.ApplyState {
		case "confirmed", "pending", "failed", "unknown":
			state = &hb.ApplyState
		}
		agentVersion := truncate(strings.TrimSpace(hb.AgentVersion), 100)
		_, err = tx.Exec(ctx, `INSERT INTO agents(name, last_seen, agent_version, config_etag, singbox_running, apply_error, apply_state)
			VALUES ($1,$2,NULLIF($3,''),NULLIF($4,''),$5,NULLIF($6,''),$7) ON CONFLICT (name) DO UPDATE SET
			last_seen = excluded.last_seen, agent_version = excluded.agent_version,
			config_etag = excluded.config_etag, singbox_running = excluded.singbox_running,
			apply_error = excluded.apply_error, apply_state = excluded.apply_state`,
			name, s.now(), agentVersion, strings.Trim(hb.ConfigETag, `"`), hb.SingboxRunning, applied, state)
		if err != nil {
			return err
		}
		if hb.XTCP != nil {
			if err := recordXTCPReport(ctx, tx, name, s.now(), *hb.XTCP); err != nil {
				return err
			}
		}
		if err := recordAgentUpdate(ctx, tx, name, s.now(), hb.Update); err != nil {
			return err
		}
		changed := false
		if isPublicIPv4(address) {
			tag, err := tx.Exec(ctx, `UPDATE hosts SET observed_public_ipv4 = $3::text::inet
				WHERE name = $1 AND agent_token_hash = $2 AND public_host = ''
				AND observed_public_ipv4 IS DISTINCT FROM $3::text::inet`, name, tokenHash, address.String())
			if err != nil {
				return err
			}
			changed = tag.RowsAffected() != 0
		}
		if canSeedPool {
			tag, err := tx.Exec(ctx, `INSERT INTO egress_ips(ip, host, note)
				SELECT $2::text::inet, $1, 'Detected by macOS Agent'
				WHERE NOT EXISTS (SELECT 1 FROM egress_ips WHERE host = $1)
				ON CONFLICT (ip) DO NOTHING`, name, localAddress.String())
			if err != nil {
				return err
			}
			changed = changed || tag.RowsAffected() != 0
		}
		if changed {
			return bumpVersion(ctx, tx)
		}
		return nil
	}
	if canSeedPool {
		// Serialize the empty-pool check with other heartbeats and manual inventory edits.
		return s.write(ctx, save)
	}
	return pgx.BeginFunc(ctx, s.pool, save)
}

func (s *store) recordProbes(ctx context.Context, tx pgx.Tx, kind, source string, probes []probeInput) error {
	if len(probes) > maxResults {
		return failure(400, "results must be a list of at most %d items", maxResults)
	}
	if len(probes) > 0 {
		rows := make([][]any, 0, len(probes))
		now := s.now()
		for i, p := range probes {
			if p.Subject == nil || p.Target == nil || p.OK == nil {
				return failure(400, "probe result %d needs subject, target and ok", i+1)
			}
			rows = append(rows, []any{kind, *p.Subject, source, *p.Target, *p.OK, p.LatencyMS, truncate(p.Detail, 200), now})
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"probes"},
			[]string{"kind", "subject", "source", "target", "ok", "latency_ms", "detail", "at"}, pgx.CopyFromRows(rows)); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, "DELETE FROM probes WHERE at < $1", s.now()-probeRetention)
	return err
}

type probeSeries struct {
	Source    string   `json:"source"`
	Target    string   `json:"target"`
	OK        bool     `json:"ok"`
	LatencyMS *float64 `json:"latency_ms"`
	Detail    string   `json:"detail"`
	At        float64  `json:"at"`
	History   []bool   `db:"-" json:"history"`
}

type probeSample struct {
	probeSeries
	Subject string
}

func loadSeries(ctx context.Context, db database, kind string, subjects []string) (map[string][]probeSeries, error) {
	out := make(map[string][]probeSeries)
	if len(subjects) == 0 {
		return out, nil
	}
	samples, err := rowsOf[probeSample](ctx, db, `SELECT subject, source, target, ok, latency_ms, detail, at FROM (
		SELECT subject, source, target, ok, latency_ms, detail, at, id,
			row_number() OVER (PARTITION BY subject, source, target ORDER BY at DESC, id DESC) AS position
		FROM probes WHERE kind = $1 AND subject = ANY($2::text[])
		) ranked WHERE position <= $3 ORDER BY subject, source, target, at DESC, id DESC`, kind, subjects, probeHistory)
	if err != nil {
		return nil, err
	}
	for _, p := range samples {
		series := out[p.Subject]
		if len(series) == 0 || series[len(series)-1].Source != p.Source || series[len(series)-1].Target != p.Target {
			series = append(series, p.probeSeries)
		}
		last := &series[len(series)-1]
		last.History = append(last.History, p.OK)
		out[p.Subject] = series
	}
	for _, series := range out {
		for i := range series {
			slices.Reverse(series[i].History)
		}
	}
	return out, nil
}

type agentView struct {
	Name           string  `json:"name"`
	LastSeen       float64 `json:"last_seen"`
	Age            float64 `db:"-" json:"age"`
	AgentVersion   *string `json:"agent_version"`
	ConfigETag     *string `json:"config_etag"`
	InSync         bool    `db:"-" json:"in_sync"`
	SingboxRunning *bool   `json:"singbox_running"`
	ApplyError     *string `json:"apply_error"`
	ApplyState     *string `json:"apply_state"`
}

type entryView struct {
	probeEntry
	Probes []probeSeries `json:"probes"`
	Best   *probeSeries  `json:"best"`
}

type ipHealth struct {
	ipView
	Devices int           `json:"devices"`
	Probes  []probeSeries `json:"probes"`
}

type topologyView struct {
	Now               float64           `json:"now"`
	Version           int64             `json:"version"`
	ServerConfigETags map[string]string `json:"server_config_etags"`
	Hosts             []hostView        `json:"hosts"`
	EgressTargets     []string          `json:"egress_targets"`
	Agents            []agentView       `json:"agents"`
	Entries           []entryView       `json:"entries"`
	IPs               []ipHealth        `json:"ips"`
}

func decodeMonitor(cfg settings) (monitorSettings, error) {
	var monitor monitorSettings
	err := json.Unmarshal(cfg.Monitor, &monitor)
	return monitor, err
}

func (s *store) topology(ctx context.Context, db database, monitor monitorSettings) (topologyView, error) {
	topo := topologyView{
		Now: s.now(), ServerConfigETags: map[string]string{}, EgressTargets: orEmpty(monitor.Targets),
	}
	var err error
	if topo.Version, err = version(ctx, db); err != nil {
		return topo, err
	}
	if topo.Hosts, err = listHosts(ctx, db); err != nil {
		return topo, err
	}
	for _, view := range topo.Hosts {
		h, err := getHost(ctx, db, view.Name)
		if err != nil {
			return topo, err
		}
		cfg, err := serverConfig(ctx, db, h)
		if err != nil {
			return topo, err
		}
		topo.ServerConfigETags[view.Name] = cfg.ETag
	}
	topo.Agents, err = rowsOf[agentView](ctx, db, `SELECT a.name, a.last_seen, a.agent_version, a.config_etag, a.singbox_running, a.apply_error, a.apply_state
		FROM agents a JOIN hosts h ON h.name = a.name ORDER BY a.name`)
	if err != nil {
		return topo, err
	}
	for i := range topo.Agents {
		a := &topo.Agents[i]
		a.Age = topo.Now - a.LastSeen
		a.InSync = a.ConfigETag != nil && *a.ConfigETag == topo.ServerConfigETags[a.Name] &&
			(a.ApplyState == nil || *a.ApplyState == "confirmed")
	}
	topo.Entries, err = topologyEntries(ctx, db, monitor)
	if err != nil {
		return topo, err
	}
	topo.IPs, err = topologyIPs(ctx, db, topo.Now)
	return topo, err
}

func topologyEntries(ctx context.Context, db database, monitor monitorSettings) ([]entryView, error) {
	entries, err := listEntries(ctx, db, monitor)
	if err != nil {
		return nil, err
	}
	subjects := make([]string, 0, len(entries))
	for _, e := range entries {
		subjects = append(subjects, e.Name)
	}
	series, err := loadSeries(ctx, db, "entry", subjects)
	if err != nil {
		return nil, err
	}
	out := make([]entryView, 0, len(entries))
	for _, e := range entries {
		view := entryView{probeEntry: e, Probes: orEmpty(series[e.Name])}
		for i := range view.Probes {
			p := &view.Probes[i]
			if p.OK && p.LatencyMS != nil && (view.Best == nil || *p.LatencyMS < *view.Best.LatencyMS) {
				view.Best = p
			}
		}
		out = append(out, view)
	}
	return out, nil
}

func topologyIPs(ctx context.Context, db database, now float64) ([]ipHealth, error) {
	ips, err := listIPs(ctx, db, "", now)
	if err != nil {
		return nil, err
	}
	subjects := make([]string, 0, len(ips))
	for _, ip := range ips {
		subjects = append(subjects, ip.IP)
	}
	series, err := loadSeries(ctx, db, "egress", subjects)
	if err != nil {
		return nil, err
	}
	counts, err := rowsOf[struct {
		IP    string
		Count int
	}](ctx, db, `SELECT host(u.egress_ip) AS ip, count(*) FROM users u
		JOIN devices d ON d.user_name = u.name WHERE u.egress_ip IS NOT NULL AND d.revoked_at IS NULL GROUP BY u.egress_ip`)
	if err != nil {
		return nil, err
	}
	devices := make(map[string]int, len(counts))
	for _, c := range counts {
		devices[c.IP] = c.Count
	}
	out := make([]ipHealth, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ipHealth{ipView: ip, Devices: devices[ip.IP], Probes: orEmpty(series[ip.IP])})
	}
	return out, nil
}
