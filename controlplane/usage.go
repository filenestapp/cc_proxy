package main

// Per-device traffic usage: exit agents report upload and download bytes per VLESS user name and UTC hour
// (POST /agent/usage, measured as described in egress/agent/usage.go), and administrators read them per calendar
// day, week, or month in Asia/Singapore (GET /admin/usage).
//
// Identity. Usage belongs to devices.id, which stays the same when a device signs in again, is revoked and
// re-registered, or its user moves to another exit, and which is never reused: a deleted account recreated with
// the same names gets new IDs. A report names a device by its VLESS user name "<user>/<device>" and, from current
// agents, by the SHA-256 of the VLESS UUID that carried the traffic (taken from the configuration the running
// sing-box instance has proved it loaded). The control plane records that hash for every credential it serves
// (usage_credentials), so a delayed batch lands on the device that moved the bytes, even when a deleted account was
// recreated with the same names in the same hour. The rendered server configuration is unchanged; usage_devices
// keeps the names each ID had, so history survives deletion.
//
// Without a credential. A name-only report entry resolves only when exactly one device this host served under
// those names could have existed during the reported hour. The lookup allows usageClockMargin for clock differences.
// With multiple candidates or an unrecognized credential, the bytes stay unresolved on the host and the candidate
// hours are marked incomplete.
//
// Scope. Each host writes only rows keyed by its own name, and only for devices that its configuration carried
// (usage_served and usage_credentials, recorded when the host fetches its configuration). Names the host was never
// configured with, or a credential that belongs to other names, are counted as rejected bytes on the host.
//
// Replay. A report batch is identified by (host, collector, seq); a repeated batch is acknowledged and ignored.
// Counters are additive per hour, so batches may arrive in any order.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

const usageTablesSQL = `
CREATE TABLE IF NOT EXISTS usage_devices (
    device_id bigint PRIMARY KEY,
    user_name text COLLATE "C" NOT NULL,
    device_name text COLLATE "C" NOT NULL,
    created_at double precision NOT NULL -- earliest devices.created_at seen: no traffic of this ID is older
);
CREATE INDEX IF NOT EXISTS usage_devices_names ON usage_devices(user_name, device_name);

CREATE TABLE IF NOT EXISTS usage_credentials (
    credential text PRIMARY KEY, -- hex SHA-256 of a VLESS UUID a host was configured with; never the UUID itself
    device_id bigint NOT NULL,
    first_served double precision NOT NULL
);

CREATE TABLE IF NOT EXISTS usage_served (
    host text COLLATE "C" NOT NULL,
    device_id bigint NOT NULL,
    first_served double precision NOT NULL,
    PRIMARY KEY (host, device_id)
);

CREATE TABLE IF NOT EXISTS usage_batches (
    host text COLLATE "C" NOT NULL,
    collector text NOT NULL,
    seq bigint NOT NULL,
    received_at double precision NOT NULL,
    PRIMARY KEY (host, collector, seq)
);

CREATE TABLE IF NOT EXISTS usage_host_hours (
    host text COLLATE "C" NOT NULL,
    hour bigint NOT NULL CHECK (hour % 3600 = 0),
    started boolean NOT NULL DEFAULT false,
    overflow boolean NOT NULL DEFAULT false,
    gap_seconds bigint NOT NULL DEFAULT 0 CHECK (gap_seconds >= 0),
    unattributed_up bigint NOT NULL DEFAULT 0 CHECK (unattributed_up >= 0),
    unattributed_down bigint NOT NULL DEFAULT 0 CHECK (unattributed_down >= 0),
    rejected_up bigint NOT NULL DEFAULT 0 CHECK (rejected_up >= 0),
    rejected_down bigint NOT NULL DEFAULT 0 CHECK (rejected_down >= 0),
    unresolved_up bigint NOT NULL DEFAULT 0 CHECK (unresolved_up >= 0),
    unresolved_down bigint NOT NULL DEFAULT 0 CHECK (unresolved_down >= 0),
    PRIMARY KEY (host, hour)
);
CREATE INDEX IF NOT EXISTS usage_host_hours_hour ON usage_host_hours(hour);

CREATE TABLE IF NOT EXISTS usage_device_hours (
    host text COLLATE "C" NOT NULL,
    device_id bigint NOT NULL,
    hour bigint NOT NULL CHECK (hour % 3600 = 0),
    up bigint NOT NULL DEFAULT 0 CHECK (up >= 0),
    down bigint NOT NULL DEFAULT 0 CHECK (down >= 0),
    cut bigint NOT NULL DEFAULT 0 CHECK (cut >= 0),
    ambiguous boolean NOT NULL DEFAULT false, -- legacy-named traffic that could also be this device's is unresolved
    PRIMARY KEY (hour, host, device_id)
);
CREATE INDEX IF NOT EXISTS usage_device_hours_device ON usage_device_hours(device_id, hour);

CREATE TABLE IF NOT EXISTS usage_collectors (
    host text COLLATE "C" PRIMARY KEY,
    collector text NOT NULL,
    state text NOT NULL,
    detail text NOT NULL DEFAULT '',
    agent_version text NOT NULL DEFAULT '',
    singbox_version text NOT NULL DEFAULT '',
    first_report double precision NOT NULL,
    last_report double precision NOT NULL
);
`

// ensureUsageTables is additive: a previous binary ignores these tables, so a rollback keeps working.
func ensureUsageTables(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, usageTablesSQL)
	return err
}

const (
	usageOffset        = 8 * 3600 // Asia/Singapore is UTC+8 with no daylight saving time since 1982
	usageStaleSeconds  = 300      // a collector that has not reported for this long is shown as stale
	usageMaxBatchHours = 200
	usageMaxDevices    = 10000
	usageMaxBytes      = int64(1) << 53
	usageMaxAge        = 400 * 86400
	usageBatchKeep     = 90 * 86400
	usageClockMargin   = 300 // seconds of clock difference between an exit and the control plane
)

// usageZone is fixed rather than loaded, so periods do not depend on the server's time zone database.
var usageZone = time.FixedZone("Asia/Singapore", usageOffset)

var (
	usageCollectorPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	usageCredentialPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// -- devices a host's configuration carries ----------------------------------------------------------------------

type servedDevice struct {
	ID        int64   `db:"id"`
	User      string  `db:"user_name"`
	Name      string  `db:"name"`
	CreatedAt float64 `db:"created_at"`
	UUID      string  `db:"uuid"`
}

// credentialHash is how usage reports name a VLESS credential: hex SHA-256 of its UUID in canonical text form.
func credentialHash(uuid string) string {
	digest := sha256.Sum256([]byte(strings.ToLower(uuid)))
	return hex.EncodeToString(digest[:])
}

const servedDevicesSQL = `SELECT d.id, d.user_name, d.name, d.created_at, d.uuid::text AS uuid
	FROM devices d JOIN users u ON d.user_name = u.name
	WHERE u.host = $1 AND d.revoked_at IS NULL`

func servedDevices(ctx context.Context, db database, host string) ([]servedDevice, error) {
	return rowsOf[servedDevice](ctx, db, servedDevicesSQL, host)
}

// servedCache avoids rewriting known (host, device, credential) entries on every configuration poll.
type servedCache struct {
	mu   sync.Mutex
	seen map[string]map[servedKey]bool
}

type servedKey struct {
	id   int64
	uuid string
}

func (c *servedCache) unseen(host string, devices []servedDevice) []servedDevice {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []servedDevice
	for _, d := range devices {
		if !c.seen[host][servedKey{d.ID, d.UUID}] {
			out = append(out, d)
		}
	}
	return out
}

func (c *servedCache) remember(host string, devices []servedDevice) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = map[string]map[servedKey]bool{}
	}
	if c.seen[host] == nil {
		c.seen[host] = map[servedKey]bool{}
	}
	for _, d := range devices {
		c.seen[host][servedKey{d.ID, d.UUID}] = true
	}
}

func (s *store) noteServed(ctx context.Context, db database, host string, devices []servedDevice) error {
	if len(devices) == 0 {
		return nil
	}
	n := len(devices)
	ids, users, names, created := make([]int64, n), make([]string, n), make([]string, n), make([]float64, n)
	credentials := make([]string, n)
	for i, d := range devices {
		ids[i], users[i], names[i], created[i], credentials[i] = d.ID, d.User, d.Name, d.CreatedAt, credentialHash(d.UUID)
	}
	now := s.now()
	// Signing in again moves devices.created_at forward; the identity keeps the earliest value seen.
	if _, err := db.Exec(ctx, `INSERT INTO usage_devices(device_id, user_name, device_name, created_at)
		SELECT id, u, n, c FROM unnest($1::bigint[], $2::text[], $3::text[], $4::double precision[]) AS t(id, u, n, c)
		ON CONFLICT (device_id) DO UPDATE SET created_at = LEAST(usage_devices.created_at, excluded.created_at)`,
		ids, users, names, created); err != nil {
		return err
	}
	if _, err := db.Exec(ctx, `INSERT INTO usage_credentials(credential, device_id, first_served)
		SELECT c, id, $3 FROM unnest($1::text[], $2::bigint[]) AS t(c, id) ON CONFLICT (credential) DO NOTHING`,
		credentials, ids, now); err != nil {
		return err
	}
	_, err := db.Exec(ctx, `INSERT INTO usage_served(host, device_id, first_served)
		SELECT $1, id, $3 FROM unnest($2::bigint[]) AS t(id) ON CONFLICT (host, device_id) DO NOTHING`, host, ids, now)
	return err
}

// recordServed runs after a host fetched its configuration. It is best-effort: configuration delivery never waits
// for or fails on usage bookkeeping, and ingestion repeats the check for devices the host serves right now.
func (a *api) recordServed(ctx context.Context, host string, devices []servedDevice) {
	fresh := a.served.unseen(host, devices)
	if len(fresh) == 0 {
		return
	}
	if err := a.store.noteServed(ctx, a.store.pool, host, fresh); err != nil {
		if ctx.Err() == nil {
			log.Printf("record usage devices for %s: %v", host, err)
		}
		return
	}
	a.served.remember(host, fresh)
}

// -- ingestion -------------------------------------------------------------------------------------------------

type usageCount struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
	Cut  int64 `json:"cut"`
}

type usageDeviceInput struct {
	Name       string `json:"name"`
	Credential string `json:"credential"` // hex SHA-256 of the VLESS UUID; empty from agents that cannot prove it
	usageCount
}

type usageHourInput struct {
	Hour         int64              `json:"hour"`
	Started      bool               `json:"started"`
	Overflow     bool               `json:"overflow"`
	GapSeconds   int64              `json:"gap_seconds"`
	Unattributed usageCount         `json:"unattributed"`
	Devices      []usageDeviceInput `json:"devices"`
}

type usageReportInput struct {
	Collector      string           `json:"collector"`
	AgentVersion   string           `json:"agent_version"`
	SingboxVersion string           `json:"singbox_version"`
	State          string           `json:"state"`
	Detail         string           `json:"detail"`
	Seq            *int64           `json:"seq"`
	Hours          []usageHourInput `json:"hours"`
}

func (c usageCount) valid() bool {
	return c.Up >= 0 && c.Down >= 0 && c.Cut >= 0 && c.Up < usageMaxBytes && c.Down < usageMaxBytes && c.Cut < usageMaxBytes
}

func (in *usageReportInput) validate(now float64) error {
	if !usageCollectorPattern.MatchString(in.Collector) {
		return failure(400, "collector must be 1-64 letters, digits, '-' or '_'")
	}
	if !slices.Contains([]string{"collecting", "unavailable", "error", "starting"}, in.State) {
		return failure(400, "state must be one of collecting, unavailable, error, starting")
	}
	in.Detail, in.AgentVersion, in.SingboxVersion = truncate(in.Detail, 500), truncate(in.AgentVersion, 100), truncate(in.SingboxVersion, 100)
	if in.Seq == nil {
		if len(in.Hours) != 0 {
			return failure(400, "hours need a batch seq")
		}
		return nil
	}
	if *in.Seq < 1 {
		return failure(400, "seq must be positive")
	}
	if len(in.Hours) > usageMaxBatchHours {
		return failure(413, "at most %d hours per report", usageMaxBatchHours)
	}
	for _, h := range in.Hours {
		if h.Hour%3600 != 0 || float64(h.Hour) > now+3600 || float64(h.Hour) < now-usageMaxAge {
			return failure(400, "hour %d must be a UTC hour start within the last 400 days", h.Hour)
		}
		if h.GapSeconds < 0 || h.GapSeconds > usageMaxAge || !h.Unattributed.valid() {
			return failure(400, "hour %d has invalid counters", h.Hour)
		}
		if len(h.Devices) > usageMaxDevices {
			return failure(413, "at most %d devices per hour", usageMaxDevices)
		}
		for _, d := range h.Devices {
			if !d.valid() {
				return failure(400, "hour %d has invalid counters for %q", h.Hour, d.Name)
			}
			if len(d.Name) > 200 {
				return failure(400, "device names are at most 200 bytes")
			}
			if d.Credential != "" && !usageCredentialPattern.MatchString(d.Credential) {
				return failure(400, "credential must be a lowercase hex SHA-256")
			}
		}
	}
	return nil
}

// usageName checks a reported VLESS user name "<user>/<device>".
func usageName(name string) bool {
	user, device, found := strings.Cut(name, "/")
	return found && user != "" && device != "" && !strings.Contains(device, "/")
}

type usageIdentity struct {
	ID        int64   `db:"device_id"`
	Base      string  `db:"base"`
	CreatedAt float64 `db:"created_at"`
}

// usageResolver knows the identities and credentials a host was configured with under the names in one report.
type usageResolver struct {
	byCredential map[string]usageIdentity
	byName       map[string][]usageIdentity
}

type usageOutcome int

const (
	usageResolved usageOutcome = iota
	usageRejected
	usageUnresolved
)

// resolve attributes one report entry in one hour. Unresolved returns every device it could belong to.
func (r usageResolver) resolve(d usageDeviceInput, hour int64) (usageOutcome, []int64) {
	if !usageName(d.Name) {
		return usageRejected, nil
	}
	if identity, known := r.byCredential[d.Credential]; known && d.Credential != "" {
		if identity.Base != d.Name {
			return usageRejected, nil // a credential served under other names
		}
		return usageResolved, []int64{identity.ID}
	}
	// Use the name and hour to find plausible devices. An unrecognized credential cannot confirm a device.
	var plausible []int64
	for _, identity := range r.byName[d.Name] {
		if identity.CreatedAt < float64(hour+3600+usageClockMargin) {
			plausible = append(plausible, identity.ID)
		}
	}
	switch {
	case len(plausible) == 0:
		return usageRejected, nil
	case len(plausible) == 1 && d.Credential == "":
		return usageResolved, plausible
	default:
		return usageUnresolved, plausible
	}
}

func (s *store) usageResolver(ctx context.Context, tx pgx.Tx, host string, entries []usageDeviceInput) (usageResolver, error) {
	r := usageResolver{byCredential: map[string]usageIdentity{}, byName: map[string][]usageIdentity{}}
	var names, credentials []string
	for _, d := range entries {
		if usageName(d.Name) {
			names = append(names, d.Name)
			if d.Credential != "" {
				credentials = append(credentials, d.Credential)
			}
		}
	}
	if len(names) == 0 {
		return r, nil
	}
	// Devices the host serves right now count as served even if the configuration poll was not recorded.
	current, err := servedDevices(ctx, tx, host)
	if err != nil {
		return r, err
	}
	var wanted []servedDevice
	for _, d := range current {
		if slices.Contains(names, d.User+"/"+d.Name) || slices.Contains(credentials, credentialHash(d.UUID)) {
			wanted = append(wanted, d)
		}
	}
	if err := s.noteServed(ctx, tx, host, wanted); err != nil {
		return r, err
	}
	identities, err := rowsOf[usageIdentity](ctx, tx, `SELECT ud.device_id, ud.user_name || '/' || ud.device_name AS base,
		ud.created_at FROM usage_devices ud JOIN usage_served sv ON sv.device_id = ud.device_id AND sv.host = $1
		WHERE ud.user_name || '/' || ud.device_name = ANY($2)`, host, names)
	if err != nil {
		return r, err
	}
	for _, identity := range identities {
		r.byName[identity.Base] = append(r.byName[identity.Base], identity)
	}
	rows, err := tx.Query(ctx, `SELECT uc.credential, ud.device_id, ud.user_name || '/' || ud.device_name, ud.created_at
		FROM usage_credentials uc JOIN usage_devices ud ON ud.device_id = uc.device_id
		JOIN usage_served sv ON sv.device_id = uc.device_id AND sv.host = $1
		WHERE uc.credential = ANY($2)`, host, credentials)
	if err != nil {
		return r, err
	}
	defer rows.Close()
	for rows.Next() {
		var credential string
		var identity usageIdentity
		if err := rows.Scan(&credential, &identity.ID, &identity.Base, &identity.CreatedAt); err != nil {
			return r, err
		}
		r.byCredential[credential] = identity
	}
	return r, rows.Err()
}

type usageResult struct {
	Duplicate  bool     `json:"duplicate"`
	Hours      int      `json:"hours"`
	Rejected   []string `json:"rejected"`
	Unresolved []string `json:"unresolved"`
}

func (s *store) recordUsage(ctx context.Context, host, token string, in usageReportInput) (usageResult, error) {
	result := usageResult{Rejected: []string{}, Unresolved: []string{}}
	now := s.now()
	if err := in.validate(now); err != nil {
		return result, err
	}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var name string
		err := tx.QueryRow(ctx, "SELECT name FROM hosts WHERE name = $1 AND agent_token_hash = $2 FOR KEY SHARE",
			host, hashToken(token)).Scan(&name)
		if errors.Is(err, pgx.ErrNoRows) {
			return failure(401, "unauthorized")
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO usage_collectors(host, collector, state, detail, agent_version,
			singbox_version, first_report, last_report) VALUES ($1,$2,$3,$4,$5,$6,$7,$7)
			ON CONFLICT (host) DO UPDATE SET collector = excluded.collector, state = excluded.state,
			detail = excluded.detail, agent_version = excluded.agent_version,
			singbox_version = excluded.singbox_version, last_report = excluded.last_report`,
			host, in.Collector, in.State, in.Detail, in.AgentVersion, in.SingboxVersion, now); err != nil {
			return err
		}
		if in.Seq == nil {
			return nil
		}
		tag, err := tx.Exec(ctx, `INSERT INTO usage_batches(host, collector, seq, received_at) VALUES ($1,$2,$3,$4)
			ON CONFLICT DO NOTHING`, host, in.Collector, *in.Seq, now)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			result.Duplicate = true
			return nil
		}
		if _, err := tx.Exec(ctx, "DELETE FROM usage_batches WHERE host = $1 AND received_at < $2", host, now-usageBatchKeep); err != nil {
			return err
		}
		var entries []usageDeviceInput
		for _, h := range in.Hours {
			entries = append(entries, h.Devices...)
		}
		resolver, err := s.usageResolver(ctx, tx, host, entries)
		if err != nil {
			return err
		}
		note := func(list *[]string, name string) {
			if !slices.Contains(*list, name) {
				*list = append(*list, name)
			}
		}
		const deviceHour = `INSERT INTO usage_device_hours(host, device_id, hour, up, down, cut, ambiguous)
			VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (hour, host, device_id) DO UPDATE SET
			up = usage_device_hours.up + excluded.up, down = usage_device_hours.down + excluded.down,
			cut = usage_device_hours.cut + excluded.cut, ambiguous = usage_device_hours.ambiguous OR excluded.ambiguous`
		batch := &pgx.Batch{}
		for _, h := range in.Hours {
			var rejected, unresolved usageCount
			for _, d := range h.Devices {
				outcome, ids := resolver.resolve(d, h.Hour)
				switch outcome {
				case usageResolved:
					batch.Queue(deviceHour, host, ids[0], h.Hour, d.Up, d.Down, d.Cut, false)
				case usageRejected:
					rejected.Up += d.Up
					rejected.Down += d.Down
					note(&result.Rejected, d.Name)
				case usageUnresolved:
					// Counted once, on the host; each device it could belong to shows the hour as incomplete.
					unresolved.Up += d.Up
					unresolved.Down += d.Down
					note(&result.Unresolved, d.Name)
					for _, id := range ids {
						batch.Queue(deviceHour, host, id, h.Hour, 0, 0, 0, true)
					}
				}
			}
			batch.Queue(`INSERT INTO usage_host_hours(host, hour, started, overflow, gap_seconds, unattributed_up,
				unattributed_down, rejected_up, rejected_down, unresolved_up, unresolved_down)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
				ON CONFLICT (host, hour) DO UPDATE SET started = usage_host_hours.started OR excluded.started,
				overflow = usage_host_hours.overflow OR excluded.overflow,
				gap_seconds = usage_host_hours.gap_seconds + excluded.gap_seconds,
				unattributed_up = usage_host_hours.unattributed_up + excluded.unattributed_up,
				unattributed_down = usage_host_hours.unattributed_down + excluded.unattributed_down,
				rejected_up = usage_host_hours.rejected_up + excluded.rejected_up,
				rejected_down = usage_host_hours.rejected_down + excluded.rejected_down,
				unresolved_up = usage_host_hours.unresolved_up + excluded.unresolved_up,
				unresolved_down = usage_host_hours.unresolved_down + excluded.unresolved_down`,
				host, h.Hour, h.Started, h.Overflow, h.GapSeconds, h.Unattributed.Up, h.Unattributed.Down,
				rejected.Up, rejected.Down, unresolved.Up, unresolved.Down)
		}
		result.Hours = len(in.Hours)
		return tx.SendBatch(ctx, batch).Close()
	})
	if err != nil {
		return usageResult{Rejected: []string{}, Unresolved: []string{}}, err
	}
	return result, nil
}

func (a *api) agentUsage(r *apiRequest) (response, error) {
	var body usageReportInput
	if err := r.decode(&body, "collector", "state"); err != nil {
		return response{}, err
	}
	result, err := a.store.recordUsage(r.Context(), r.Agent, r.Token, body)
	return ok(result, err)
}

// -- report ----------------------------------------------------------------------------------------------------

type usagePeriod struct {
	Kind       string
	Start, End time.Time // in usageZone; End is exclusive
}

func parseUsagePeriod(kind, date string, now time.Time) (usagePeriod, error) {
	if kind == "" {
		kind = "day"
	}
	day := now.In(usageZone)
	if date != "" {
		parsed, err := time.ParseInLocation("2006-01-02", date, usageZone)
		if err != nil {
			return usagePeriod{}, failure(400, "date must be YYYY-MM-DD")
		}
		day = parsed
	}
	start := time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, usageZone)
	switch kind {
	case "day":
		return usagePeriod{kind, start, start.AddDate(0, 0, 1)}, nil
	case "week": // weeks start on Monday
		start = start.AddDate(0, 0, -((int(start.Weekday()) + 6) % 7))
		return usagePeriod{kind, start, start.AddDate(0, 0, 7)}, nil
	case "month":
		start = time.Date(start.Year(), start.Month(), 1, 0, 0, 0, 0, usageZone)
		return usagePeriod{kind, start, start.AddDate(0, 1, 0)}, nil
	}
	return usagePeriod{}, failure(400, "period must be day, week, or month")
}

func (p usagePeriod) previous() usagePeriod {
	q, _ := parseUsagePeriod(p.Kind, p.Start.Add(-time.Hour).Format("2006-01-02"), p.Start)
	return q
}

type usageRow struct {
	DeviceID    int64    `db:"device_id" json:"device_id"`
	User        string   `db:"user_name" json:"user"`
	Device      string   `db:"device_name" json:"device"`
	DeviceState string   `db:"device_state" json:"device_state"`
	Measured    bool     `db:"measured" json:"-"`
	Upload      int64    `db:"up" json:"upload"`
	Download    int64    `db:"down" json:"download"`
	Total       int64    `db:"-" json:"total"`
	Cut         int64    `db:"cut" json:"cut_connections"`
	Started     bool     `db:"started" json:"-"`
	Overflow    bool     `db:"overflow" json:"-"`
	GapSeconds  int64    `db:"gap_seconds" json:"gap_seconds"`
	Ambiguous   bool     `db:"ambiguous" json:"-"`
	Hosts       []string `db:"hosts" json:"hosts"`
	Status      string   `db:"-" json:"status"`
	Reasons     []string `db:"-" json:"reasons"`
}

type usageCollectorView struct {
	Host           string   `db:"host" json:"host"`
	Collector      *string  `db:"collector" json:"collector"`
	State          *string  `db:"state" json:"state"`
	Detail         *string  `db:"detail" json:"detail"`
	AgentVersion   *string  `db:"agent_version" json:"agent_version"`
	SingboxVersion *string  `db:"singbox_version" json:"singbox_version"`
	FirstReport    *float64 `db:"first_report" json:"first_report"`
	LastReport     *float64 `db:"last_report" json:"last_report"`
	Status         string   `db:"-" json:"status"`
	Note           string   `db:"-" json:"note"`
}

type usageHostView struct {
	Host             string `db:"host" json:"host"`
	UnattributedUp   int64  `db:"unattributed_up" json:"unattributed_upload"`
	UnattributedDown int64  `db:"unattributed_down" json:"unattributed_download"`
	RejectedUp       int64  `db:"rejected_up" json:"rejected_upload"`
	RejectedDown     int64  `db:"rejected_down" json:"rejected_download"`
	UnresolvedUp     int64  `db:"unresolved_up" json:"unresolved_upload"`
	UnresolvedDown   int64  `db:"unresolved_down" json:"unresolved_download"`
}

// The status of a device in a period:
//
//	unavailable  no collector measured it (no agent support, collection off, or before history began)
//	complete     measured, possibly zero, with no known loss
//	incomplete   measured, with the reasons listed
func (r *usageRow) classify() {
	r.Total = r.Upload + r.Download
	r.Reasons = []string{}
	if r.Hosts == nil {
		r.Hosts = []string{}
	}
	if !r.Measured {
		r.Status = "unavailable"
		return
	}
	if r.Started {
		r.Reasons = append(r.Reasons, "collection started during this period; earlier traffic is not counted")
	}
	if r.GapSeconds > 0 {
		r.Reasons = append(r.Reasons, fmt.Sprintf("the collector missed %s of sing-box activity", humanSeconds(r.GapSeconds)))
	}
	if r.Overflow {
		r.Reasons = append(r.Reasons, "more than 1000 connections closed while the collector was disconnected")
	}
	if r.Ambiguous {
		r.Reasons = append(r.Reasons, "an exit reported traffic under this device's names without enough evidence "+
			"to identify the device; the bytes are counted as unresolved on the exit")
	}
	if r.Cut > 0 {
		r.Reasons = append(r.Reasons, fmt.Sprintf("%d connection(s) were cut by a sing-box reload; the last 250 ms of each is not counted", r.Cut))
	}
	r.Status = "complete"
	if len(r.Reasons) > 0 {
		r.Status = "incomplete"
	}
}

func humanSeconds(s int64) string {
	switch {
	case s < 120:
		return fmt.Sprintf("%d s", s)
	case s < 7200:
		return fmt.Sprintf("%d min", s/60)
	default:
		return fmt.Sprintf("%.1f h", float64(s)/3600)
	}
}

func (s *store) usageReport(ctx context.Context, period usagePeriod, user, device string) (object, error) {
	from, to := period.Start.Unix(), period.End.Unix()
	nowTime := s.clock()
	var out object
	err := s.snapshot(ctx, func(tx pgx.Tx) error {
		rows, err := rowsOf[usageRow](ctx, tx, `
			WITH hours AS (
				SELECT dh.device_id, dh.host, dh.hour, dh.up, dh.down, dh.cut, dh.ambiguous, hh.started, hh.overflow, hh.gap_seconds
				FROM usage_device_hours dh JOIN usage_host_hours hh ON hh.host = dh.host AND hh.hour = dh.hour
				WHERE dh.hour >= $1 AND dh.hour < $2),
			agg AS (
				SELECT device_id, sum(up)::bigint AS up, sum(down)::bigint AS down, sum(cut)::bigint AS cut,
					bool_or(started) AS started, bool_or(overflow) AS overflow, sum(gap_seconds)::bigint AS gap_seconds,
					bool_or(ambiguous) AS ambiguous,
					array_agg(DISTINCT host ORDER BY host) AS hosts
				FROM hours GROUP BY device_id),
			identities AS (
				SELECT device_id, user_name, device_name FROM usage_devices
				UNION ALL
				SELECT d.id, d.user_name, d.name FROM devices d
				WHERE NOT EXISTS (SELECT 1 FROM usage_devices ud WHERE ud.device_id = d.id))
			SELECT i.device_id, i.user_name, i.device_name,
				CASE WHEN d.id IS NULL THEN 'deleted' WHEN d.revoked_at IS NOT NULL THEN 'revoked' ELSE 'active' END AS device_state,
				agg.device_id IS NOT NULL AS measured, COALESCE(agg.up, 0) AS up, COALESCE(agg.down, 0) AS down,
				COALESCE(agg.cut, 0) AS cut, COALESCE(agg.started, false) AS started,
				COALESCE(agg.overflow, false) AS overflow, COALESCE(agg.gap_seconds, 0) AS gap_seconds,
				COALESCE(agg.ambiguous, false) AS ambiguous, agg.hosts
			FROM identities i LEFT JOIN agg ON agg.device_id = i.device_id LEFT JOIN devices d ON d.id = i.device_id
			WHERE ($3 = '' OR i.user_name = $3) AND ($4 = '' OR i.device_name = $4)
				AND (agg.device_id IS NOT NULL OR (d.id IS NOT NULL AND d.revoked_at IS NULL))
			ORDER BY i.user_name, i.device_name, i.device_id`, from, to, user, device)
		if err != nil {
			return err
		}
		var up, down int64
		for i := range rows {
			rows[i].classify()
			up += rows[i].Upload
			down += rows[i].Download
		}
		names, err := rowsOf[struct {
			User   string `db:"user_name"`
			Device string `db:"device_name"`
		}](ctx, tx, `SELECT DISTINCT user_name, device_name FROM (
				SELECT user_name, device_name FROM usage_devices UNION SELECT user_name, name FROM devices) n
			ORDER BY user_name, device_name`)
		if err != nil {
			return err
		}
		users, devices := []string{}, []string{}
		for _, n := range names {
			if !slices.Contains(users, n.User) {
				users = append(users, n.User)
			}
			if (user == "" || n.User == user) && !slices.Contains(devices, n.Device) {
				devices = append(devices, n.Device)
			}
		}
		slices.Sort(devices)
		periods, err := columnOf[time.Time](ctx, tx, `SELECT DISTINCT date_trunc($1, to_timestamp(hour + $2) AT TIME ZONE 'UTC')
			FROM (SELECT DISTINCT hour FROM usage_host_hours) h ORDER BY 1 DESC LIMIT 500`, period.Kind, usageOffset)
		if err != nil {
			return err
		}
		recorded := make([]string, len(periods))
		for i, p := range periods {
			recorded[i] = p.Format("2006-01-02")
		}
		collectors, err := rowsOf[usageCollectorView](ctx, tx, `SELECT h.name AS host, c.collector, c.state, c.detail,
			c.agent_version, c.singbox_version, c.first_report, c.last_report
			FROM hosts h LEFT JOIN usage_collectors c ON c.host = h.name ORDER BY h.name`)
		if err != nil {
			return err
		}
		now := float64(nowTime.UnixMicro()) / 1e6
		for i := range collectors {
			c := &collectors[i]
			switch {
			case c.State == nil:
				c.Status, c.Note = "unavailable", "This exit's agent does not report usage. Install the current exit agent."
			case now-*c.LastReport > usageStaleSeconds:
				c.Status, c.Note = "stale", "No usage report for "+humanSeconds(int64(now-*c.LastReport))
			default:
				c.Status, c.Note = *c.State, *c.Detail
			}
		}
		hosts, err := rowsOf[usageHostView](ctx, tx, `SELECT host, sum(unattributed_up)::bigint AS unattributed_up,
			sum(unattributed_down)::bigint AS unattributed_down, sum(rejected_up)::bigint AS rejected_up,
			sum(rejected_down)::bigint AS rejected_down, sum(unresolved_up)::bigint AS unresolved_up,
			sum(unresolved_down)::bigint AS unresolved_down FROM usage_host_hours WHERE hour >= $1 AND hour < $2
			GROUP BY host HAVING sum(unattributed_up + unattributed_down + rejected_up + rejected_down +
				unresolved_up + unresolved_down) > 0
			ORDER BY host`, from, to)
		if err != nil {
			return err
		}
		var next any
		if period.End.Before(nowTime) {
			next = period.End.Format("2006-01-02")
		}
		out = object{
			"period": period.Kind, "start": period.Start.Format("2006-01-02"), "end": period.End.Format("2006-01-02"),
			"timezone": "Asia/Singapore", "week_start": "Monday",
			"in_progress": !nowTime.Before(period.Start) && nowTime.Before(period.End),
			"previous":    period.previous().Start.Format("2006-01-02"), "next": next,
			"recorded_periods": recorded, "user": user, "device": device, "users": users, "devices": devices,
			"rows": orEmpty(rows), "totals": object{"upload": up, "download": down, "total": up + down},
			"collectors": orEmpty(collectors), "hosts": orEmpty(hosts),
		}
		return nil
	})
	return out, err
}

func (a *api) usageList(r *apiRequest) (response, error) {
	q := r.URL.Query()
	period, err := parseUsagePeriod(q.Get("period"), q.Get("date"), a.store.clock())
	if err != nil {
		return response{}, err
	}
	user, device := strings.TrimSpace(q.Get("user")), strings.TrimSpace(q.Get("device"))
	return ok(a.store.usageReport(r.Context(), period, user, device))
}
