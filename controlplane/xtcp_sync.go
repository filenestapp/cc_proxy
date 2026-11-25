package main

// XTCP mapping sync through the exit agent (issue #45).
//
// A committed change to a host's XTCP mappings (assign, reassign, release, a user removed, new XTCP settings)
// changes the fingerprint of the host's frpc configuration. The next agent fetch publishes it as a new desired
// generation: a number from one global sequence, so it only ever grows for a host, even when XTCP is disabled and
// enabled again. An upgraded agent (egress/agent/xtcp.go) polls
//
//	GET /agent/xtcp?ca_file=...[&log_file=...]   (host agent token) 204 for a public-entry host, else the desired
//	                                             generation, its fingerprint, the rendered frpc.toml, the CA and
//	                                             one digest per proxy. ETag "xtcp-<generation>-<fingerprint>".
//
// and reports in its heartbeat (POST /agent/report, field "xtcp") the generation it last attempted, the outcome,
// and the generation it last confirmed: the one the running frpc loaded and frps accepted, proved by frpc's live
// status listing every proxy as running. Only a confirmation of the current desired generation (same number and
// fingerprint) counts as applied. A late or repeated confirmation of an older generation is kept for history but
// marks nothing ready, and a report never moves the recorded generations backwards.
//
// A mapping (one port) is ready when the confirmed proxy set holds its digest and the host's sing-box runs the
// current server configuration. Hosts whose agent never reported "xtcp" run an agent from before this change:
// their mappings are "upgrade_needed" (run the install command once).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

// All additive: a previous binary ignores the new columns, table and sequence, so rollback keeps working.
var xtcpSyncSQL = []string{
	`CREATE SEQUENCE IF NOT EXISTS xtcp_generation_seq`,
	`ALTER TABLE host_xtcp ADD COLUMN IF NOT EXISTS desired_generation bigint NOT NULL DEFAULT 0,
		ADD COLUMN IF NOT EXISTS desired_sha256 text NOT NULL DEFAULT ''`,
	`CREATE TABLE IF NOT EXISTS host_xtcp_agent (
		host text COLLATE "C" PRIMARY KEY REFERENCES host_xtcp(host) ON DELETE CASCADE,
		reported_at double precision NOT NULL,
		generation bigint NOT NULL DEFAULT 0,
		state text NOT NULL DEFAULT '',
		error text NOT NULL DEFAULT '',
		applied_generation bigint NOT NULL DEFAULT 0,
		applied_sha256 text NOT NULL DEFAULT '',
		applied_proxies jsonb NOT NULL DEFAULT '[]'
	)`,
}

// Agent-reported XTCP states for the generation it last attempted.
const (
	xtcpAgentApplied = "applied" // confirmed by live frpc status
	xtcpAgentPending = "pending" // written or reloaded, not confirmed yet (retried)
	xtcpAgentFailed  = "failed"  // rejected or not confirmed; the previous working mappings were restored
)

// Per-host and per-mapping sync states shown to administrators.
const (
	xtcpSyncReady         = "ready"
	xtcpSyncPending       = "pending"
	xtcpSyncFailed        = "failed"
	xtcpSyncUpgradeNeeded = "upgrade_needed"
)

const xtcpMaxProxies = 4096

// xtcpProxyDigest identifies one rendered proxy (name, port and secret key). It lets the console tell which ports
// the running frpc already serves without the agent ever sending a key back.
func xtcpProxyDigest(m xtcpMapping) string {
	sum := sha256.Sum256([]byte("ccproxy xtcp proxy\x00" + m.ProxyName + "\x00" + strconv.Itoa(m.Port) + "\x00" + m.secretKey))
	return hex.EncodeToString(sum[:16])
}

type xtcpDesiredProxy struct {
	Name   string `json:"name"`
	Port   int    `json:"port"`
	Digest string `json:"digest"`
}

type xtcpDesired struct {
	Generation int64              `json:"generation"`
	SHA256     string             `json:"sha256"`
	FrpcTOML   string             `json:"frpc_toml"`
	CAPEM      string             `json:"ca_pem"`
	Proxies    []xtcpDesiredProxy `json:"proxies"`
}

func xtcpETag(generation int64, sha string) string {
	return "xtcp-" + strconv.FormatInt(generation, 10) + "-" + sha
}

// publishXTCP makes fingerprint the host's desired configuration and returns its generation. A new fingerprint
// takes the next number from the global sequence; an unchanged one keeps its generation.
func publishXTCP(ctx context.Context, tx pgx.Tx, hostName, fingerprint string) (int64, error) {
	var generation int64
	err := tx.QueryRow(ctx, `UPDATE host_xtcp SET desired_generation = nextval('xtcp_generation_seq'), desired_sha256 = $2
		WHERE host = $1 AND desired_sha256 <> $2 RETURNING desired_generation`, hostName, fingerprint).Scan(&generation)
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, "SELECT desired_generation FROM host_xtcp WHERE host = $1", hostName).Scan(&generation)
	}
	return generation, err
}

// xtcpDesiredFor reads the calling host's settings and mappings and publishes their fingerprint. found is false for
// a public-entry host. The common case (nothing changed) takes no write lock.
func (s *store) xtcpDesiredFor(ctx context.Context, hostName string) (x xtcpSettings, mappings []xtcpMapping, found bool, err error) {
	read := func(tx pgx.Tx) error {
		if x, found, err = getXTCP(ctx, tx, hostName); err != nil || !found {
			return err
		}
		mappings, err = xtcpMappings(ctx, tx, x)
		return err
	}
	if err = s.snapshot(ctx, read); err != nil || !found {
		return
	}
	if x.DesiredGeneration > 0 && x.DesiredSHA256 == xtcpFingerprint(x, mappings) {
		return
	}
	err = s.write(ctx, func(tx pgx.Tx) error {
		if err := read(tx); err != nil || !found {
			return err
		}
		fp := xtcpFingerprint(x, mappings)
		generation, err := publishXTCP(ctx, tx, hostName, fp)
		x.DesiredGeneration, x.DesiredSHA256 = generation, fp
		return err
	})
	return
}

// agentXTCP serves the calling host's desired frpc configuration to its agent. The paths come from the agent's
// own trusted installation settings and are validated as for the installer; they are not part of the fingerprint.
func (a *api) agentXTCP(r *apiRequest) (response, error) {
	q := r.URL.Query()
	caFile, logFile := q.Get("ca_file"), q.Get("log_file")
	if !xtcpPathPattern.MatchString(caFile) || (logFile != "" && !xtcpPathPattern.MatchString(logFile)) {
		return response{}, failure(400, "ca_file (and log_file) must be absolute paths without quotes")
	}
	x, mappings, found, err := a.store.xtcpDesiredFor(r.Context(), r.Agent)
	if err != nil || !found {
		return noContent, err
	}
	etag := xtcpETag(x.DesiredGeneration, x.DesiredSHA256)
	desired := xtcpDesired{Generation: x.DesiredGeneration, SHA256: x.DesiredSHA256,
		FrpcTOML: renderFrpcTOML(x, mappings, caFile, logFile), CAPEM: x.CAPEM}
	for _, m := range mappings {
		desired.Proxies = append(desired.Proxies, xtcpDesiredProxy{Name: m.ProxyName, Port: m.Port, Digest: xtcpProxyDigest(m)})
	}
	body, err := json.Marshal(desired)
	if err != nil {
		return response{}, err
	}
	return configResponse(r, renderedConfig{Body: body, ETag: etag}), nil
}

// xtcpReport is the "xtcp" object of an upgraded agent's heartbeat.
type xtcpReport struct {
	Generation        int64              `json:"generation"`
	State             string             `json:"state"`
	Error             string             `json:"error"`
	AppliedGeneration int64              `json:"applied_generation"`
	AppliedSHA256     string             `json:"applied_sha256"`
	AppliedProxies    []xtcpDesiredProxy `json:"applied_proxies"`
}

// recordXTCPReport stores an agent's XTCP outcome. Generations never move backwards, and nothing newer than what
// the control plane published is accepted. A public-entry host's report is ignored.
func recordXTCPReport(ctx context.Context, tx pgx.Tx, hostName string, now float64, rep xtcpReport) error {
	switch rep.State {
	case "", xtcpAgentApplied, xtcpAgentPending, xtcpAgentFailed:
	default:
		return failure(400, "xtcp.state must be applied, pending or failed")
	}
	if rep.Generation < 0 || rep.AppliedGeneration < 0 || len(rep.AppliedProxies) > xtcpMaxProxies {
		return failure(400, "invalid xtcp report")
	}
	var desired int64
	err := tx.QueryRow(ctx, "SELECT desired_generation FROM host_xtcp WHERE host = $1", hostName).Scan(&desired)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if rep.Generation > desired {
		rep.Generation, rep.State, rep.Error = 0, "", ""
	}
	if rep.AppliedGeneration > desired {
		rep.AppliedGeneration, rep.AppliedSHA256, rep.AppliedProxies = 0, "", nil
	}
	proxies, err := json.Marshal(orEmpty(rep.AppliedProxies))
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO host_xtcp_agent(host, reported_at, generation, state, error, applied_generation,
		applied_sha256, applied_proxies) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (host) DO UPDATE SET reported_at = excluded.reported_at,
		generation = CASE WHEN excluded.generation >= host_xtcp_agent.generation THEN excluded.generation ELSE host_xtcp_agent.generation END,
		state = CASE WHEN excluded.generation >= host_xtcp_agent.generation THEN excluded.state ELSE host_xtcp_agent.state END,
		error = CASE WHEN excluded.generation >= host_xtcp_agent.generation THEN excluded.error ELSE host_xtcp_agent.error END,
		applied_generation = GREATEST(excluded.applied_generation, host_xtcp_agent.applied_generation),
		applied_sha256 = CASE WHEN excluded.applied_generation > host_xtcp_agent.applied_generation THEN excluded.applied_sha256 ELSE host_xtcp_agent.applied_sha256 END,
		applied_proxies = CASE WHEN excluded.applied_generation > host_xtcp_agent.applied_generation THEN excluded.applied_proxies ELSE host_xtcp_agent.applied_proxies END`,
		hostName, now, rep.Generation, rep.State, truncate(redactXTCPError(rep.Error), 500), rep.AppliedGeneration,
		rep.AppliedSHA256, proxies)
	return err
}

// redactXTCPError drops anything that looks like a credential assignment from an agent-supplied message. The agent
// already removes the values it knows; this is the second line of defence before the text reaches the console.
func redactXTCPError(text string) string {
	lower := strings.ToLower(text)
	for _, key := range []string{"auth.token", "secretkey", "webserver.password", "password", "token ="} {
		if strings.Contains(lower, key) {
			return "details withheld: the message mentioned a credential; see the exit host's agent log"
		}
	}
	return text
}

type xtcpAgentRow struct {
	ReportedAt        float64            `db:"reported_at" json:"reported_at"`
	Generation        int64              `db:"generation" json:"generation"`
	State             string             `db:"state" json:"state"`
	Error             string             `db:"error" json:"error"`
	AppliedGeneration int64              `db:"applied_generation" json:"applied_generation"`
	AppliedSHA256     string             `db:"applied_sha256" json:"-"`
	AppliedProxies    []xtcpDesiredProxy `db:"applied_proxies" json:"-"`
}

// singboxCurrent: the host's agent confirmed the current sing-box server configuration (every entry port listens).
func singboxCurrent(ctx context.Context, db database, hostName string) (bool, error) {
	h, err := getHost(ctx, db, hostName)
	if err != nil {
		return false, err
	}
	cfg, err := serverConfig(ctx, db, h)
	if err != nil {
		return false, err
	}
	var current bool
	err = db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agents WHERE name = $1 AND config_etag = $2
		AND (apply_state IS NULL OR apply_state = 'confirmed'))`, hostName, cfg.ETag).Scan(&current)
	return current, err
}

// xtcpSyncView adds the sync state of the host and of each mapping to an XTCP view. mappings is the current list.
func xtcpSyncView(ctx context.Context, db database, x xtcpSettings, mappings []xtcpMapping, view object) error {
	fp := xtcpFingerprint(x, mappings)
	published := x.DesiredGeneration > 0 && x.DesiredSHA256 == fp
	agent, err := rowOf[xtcpAgentRow](ctx, db, `SELECT reported_at, generation, state, error, applied_generation,
		applied_sha256, applied_proxies FROM host_xtcp_agent WHERE host = $1`, x.Host)
	capable := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	singbox, err := singboxCurrent(ctx, db, x.Host)
	if err != nil {
		return err
	}
	confirmed := map[string]bool{}
	for _, p := range agent.AppliedProxies {
		confirmed[p.Digest] = true
	}
	applied := published && capable && agent.AppliedGeneration == x.DesiredGeneration && agent.AppliedSHA256 == fp
	failed := published && capable && agent.Generation == x.DesiredGeneration && agent.State == xtcpAgentFailed
	state := xtcpSyncPending
	switch {
	case !capable:
		state = xtcpSyncUpgradeNeeded
	case applied && singbox:
		state = xtcpSyncReady
	case failed:
		state = xtcpSyncFailed
	}
	sync := object{"state": state, "desired_generation": x.DesiredGeneration, "published": published,
		"singbox_current": singbox, "agent_capable": capable}
	if capable {
		sync["agent"] = agent
	}
	switch state {
	case xtcpSyncFailed:
		sync["message"] = fmt.Sprintf("Exit host %s could not activate its XTCP mappings: %s. The previous mappings stay in use; the agent retries.",
			x.Host, orText(agent.Error, "no details"))
	case xtcpSyncUpgradeNeeded:
		sync["message"] = fmt.Sprintf("Exit host %s runs an agent without XTCP sync. Run the install command on it once; later changes then apply automatically.", x.Host)
	case xtcpSyncPending:
		sync["message"] = fmt.Sprintf("Waiting for exit host %s to confirm its XTCP mappings and sing-box listeners.", x.Host)
	}
	view["sync"] = sync
	rows := make([]object, 0, len(mappings))
	for _, m := range mappings {
		status := xtcpSyncPending
		switch {
		case !capable:
			status = xtcpSyncUpgradeNeeded
		case confirmed[xtcpProxyDigest(m)]:
			// A failed update does not invalidate previously confirmed frpc mappings.
			// Their listeners still need confirmation before they can be marked ready.
			if singbox {
				status = xtcpSyncReady
			}
		case failed:
			status = xtcpSyncFailed
		}
		rows = append(rows, object{"user": m.User, "port": m.Port, "proxy_name": m.ProxyName, "primary": m.Primary, "status": status})
	}
	view["mappings"] = rows
	return nil
}

func orText(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
