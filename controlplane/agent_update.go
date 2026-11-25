package main

// Managed rollout of exit-agent releases (docs/exit-agent-updates.md).
//
//	GET    /agent/update                          (host agent token) this host's rollout target, or 204
//	GET    /agent/update/{version}/{platform}     (host agent token) a published release's binary
//	GET    /admin/agent-releases                  published releases in CP_AGENT_RELEASES
//	GET    /admin/agent-rollout                   the rollout and every host's running version and update outcome
//	PUT    /admin/agent-rollout                   {"version": V, "hosts": ["h1", ...] | "all", "paused": false}
//	POST   /admin/agent-rollout/pause             no further hosts start the update
//	POST   /admin/agent-rollout/resume
//	DELETE /admin/agent-rollout                   stop the rollout; every host keeps the release it runs
//
// A release is a directory CP_AGENT_RELEASES/<version>/ holding the exit-agent workflow's artifact: the binaries,
// SHA256SUMS, VERSION, release.json and release.json.sig. The control plane does not hold the signing key and does
// not need to trust the files: an agent installs a binary only when release.json verifies against the keys compiled
// into it and the binary matches the digest that release.json lists. The control plane decides only which hosts are
// offered which release, and when.
//
// Every PUT starts a new rollout id, also for the same version and hosts: that is how an operator retries hosts
// that rolled back or refused the release (an agent does not retry the same rollout id on its own). Pause and resume
// keep the id. Hosts report their running version ("agent_version", stored by #66 in agents.agent_version) and the
// update outcome ("update") in every heartbeat; GET /admin/agent-rollout combines them with the rollout.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// All additive: a previous binary ignores the tables, so rollback keeps working.
var agentUpdateSQL = []string{
	`CREATE SEQUENCE IF NOT EXISTS agent_rollout_seq`,
	`CREATE TABLE IF NOT EXISTS agent_rollout (
		id integer PRIMARY KEY CHECK (id = 1),
		rollout_id bigint NOT NULL,
		version text NOT NULL,
		sequence bigint NOT NULL,
		hosts text[],
		paused boolean NOT NULL DEFAULT false,
		updated_at double precision NOT NULL,
		updated_by text NOT NULL DEFAULT ''
	)`,
	`CREATE TABLE IF NOT EXISTS agent_update_status (
		host text COLLATE "C" PRIMARY KEY REFERENCES hosts(name) ON DELETE CASCADE,
		reported_at double precision NOT NULL,
		state text NOT NULL DEFAULT '',
		target_version text NOT NULL DEFAULT '',
		target_sequence bigint NOT NULL DEFAULT 0,
		rollout_id bigint NOT NULL DEFAULT 0,
		running_sequence bigint NOT NULL DEFAULT 0,
		previous_version text NOT NULL DEFAULT '',
		error text NOT NULL DEFAULT '',
		state_at double precision
	)`,
}

func ensureAgentUpdateTables(ctx context.Context, tx pgx.Tx) error {
	for _, statement := range agentUpdateSQL {
		if _, err := tx.Exec(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

var (
	agentVersionPattern = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)
	agentUpdateStates   = []string{"disabled", "idle", "current", "downloading", "confirming", "updated", "rolled_back", "rejected", "failed"}
)

// agentUpdateReport is the heartbeat's "update" object (egress/agent/update.go updater.report).
type agentUpdateReport struct {
	State           string   `json:"state"`
	TargetVersion   string   `json:"target_version"`
	TargetSequence  int64    `json:"target_sequence"`
	RolloutID       int64    `json:"rollout_id"`
	RunningSequence int64    `json:"running_sequence"`
	PreviousVersion string   `json:"previous_version"`
	Error           string   `json:"error"`
	At              *float64 `json:"at"`
}

// recordAgentUpdate stores a heartbeat's update outcome (the running version is agents.agent_version, #66).
// Malformed values are dropped rather than failing the heartbeat, which also carries sing-box health.
func recordAgentUpdate(ctx context.Context, tx pgx.Tx, hostName string, now float64, rep *agentUpdateReport) error {
	if rep == nil {
		return nil
	}
	r := *rep
	if !slices.Contains(agentUpdateStates, r.State) {
		r.State = "unknown"
	}
	if r.TargetVersion != "" && !agentVersionPattern.MatchString(r.TargetVersion) {
		r.TargetVersion = "invalid"
	}
	if r.PreviousVersion != "" && !agentVersionPattern.MatchString(r.PreviousVersion) {
		r.PreviousVersion = ""
	}
	r.TargetSequence, r.RolloutID, r.RunningSequence = max(r.TargetSequence, 0), max(r.RolloutID, 0), max(r.RunningSequence, 0)
	_, err := tx.Exec(ctx, `INSERT INTO agent_update_status(host, reported_at, state, target_version, target_sequence,
		rollout_id, running_sequence, previous_version, error, state_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (host) DO UPDATE SET reported_at = excluded.reported_at, state = excluded.state,
		target_version = excluded.target_version, target_sequence = excluded.target_sequence,
		rollout_id = excluded.rollout_id, running_sequence = excluded.running_sequence,
		previous_version = excluded.previous_version, error = excluded.error, state_at = excluded.state_at`,
		hostName, now, r.State, r.TargetVersion, r.TargetSequence, r.RolloutID, r.RunningSequence, r.PreviousVersion,
		truncate(r.Error, 300), r.At)
	return err
}

// -- published releases ----------------------------------------------------------------------------------------------

func agentReleasesDir() string { return os.Getenv("CP_AGENT_RELEASES") }

type releaseBinary struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// publishedRelease is what the control plane reads from release.json; the agent does the full, strict check.
type publishedRelease struct {
	Version     string                   `json:"version"`
	Sequence    int64                    `json:"sequence"`
	Commit      string                   `json:"commit,omitempty"`
	PublishedAt string                   `json:"published_at,omitempty"`
	Binaries    map[string]releaseBinary `json:"binaries"`
	Platforms   []string                 `json:"platforms"`
	record      []byte
	signature   string
}

func noReleases(format string, args ...any) error {
	return failure(503, "agent releases are not available (set CP_AGENT_RELEASES to the directory of published releases): "+format, args...)
}

// loadPublishedRelease reads CP_AGENT_RELEASES/<version>/release.json and its signature.
func loadPublishedRelease(dir, version string) (publishedRelease, error) {
	var rel publishedRelease
	if dir == "" {
		return rel, noReleases("CP_AGENT_RELEASES is not set")
	}
	if !agentVersionPattern.MatchString(version) || strings.Trim(version, ".") == "" {
		return rel, failure(400, "invalid agent version %q", version)
	}
	base := filepath.Join(dir, version)
	record, err := os.ReadFile(filepath.Join(base, "release.json"))
	if errors.Is(err, os.ErrNotExist) {
		return rel, failure(404, "no published agent release %s", version)
	}
	if err != nil {
		return rel, err
	}
	signature, err := os.ReadFile(filepath.Join(base, "release.json.sig"))
	if err != nil {
		return rel, failure(409, "agent release %s is not signed (release.json.sig is missing)", version)
	}
	if err := json.Unmarshal(record, &rel); err != nil {
		return rel, failure(409, "agent release %s: release.json: %v", version, err)
	}
	if rel.Version != version || rel.Sequence <= 0 || len(rel.Binaries) == 0 {
		return rel, failure(409, "agent release %s: release.json names version %q, sequence %d", version, rel.Version, rel.Sequence)
	}
	for platform, b := range rel.Binaries {
		if !slices.Contains(installPlatforms, platform) || b.File != agentFileName(platform) || !installHexPattern.MatchString(b.SHA256) {
			return rel, failure(409, "agent release %s: bad entry for %s", version, platform)
		}
		rel.Platforms = append(rel.Platforms, platform)
	}
	sort.Strings(rel.Platforms)
	rel.record, rel.signature = record, strings.TrimSpace(string(signature))
	return rel, nil
}

func listPublishedReleases(dir string) ([]publishedRelease, []object, error) {
	if dir == "" {
		return nil, nil, noReleases("CP_AGENT_RELEASES is not set")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, noReleases("%v", err)
	}
	var releases []publishedRelease
	var problems []object
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		rel, err := loadPublishedRelease(dir, e.Name())
		if err != nil {
			problems = append(problems, object{"directory": e.Name(), "error": err.Error()})
			continue
		}
		releases = append(releases, rel)
	}
	sort.Slice(releases, func(i, j int) bool { return releases[i].Sequence > releases[j].Sequence })
	return releases, problems, nil
}

// -- rollout ---------------------------------------------------------------------------------------------------------

type agentRollout struct {
	RolloutID int64    `json:"rollout_id" db:"rollout_id"`
	Version   string   `json:"version" db:"version"`
	Sequence  int64    `json:"sequence" db:"sequence"`
	Hosts     []string `json:"hosts" db:"hosts"` // nil: every host
	Paused    bool     `json:"paused" db:"paused"`
	UpdatedAt float64  `json:"updated_at" db:"updated_at"`
	UpdatedBy string   `json:"updated_by" db:"updated_by"`
}

func (r agentRollout) targets(host string) bool {
	return r.Hosts == nil || slices.Contains(r.Hosts, host)
}

func getRollout(ctx context.Context, db database) (*agentRollout, error) {
	r, err := rowOf[agentRollout](ctx, db, `SELECT rollout_id, version, sequence, hosts, paused, updated_at, updated_by
		FROM agent_rollout WHERE id = 1`)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (a *api) agentUpdateRoutes() {
	a.bind("GET /agent/update", "agent", "", a.agentUpdateOffer)
	a.bind("GET /agent/update/{version}/{platform}", "agent", "", a.agentUpdateBinary)
	a.bind("GET /admin/agent-releases", "admin", "", a.agentReleaseList)
	a.bind("GET /admin/agent-rollout", "admin", "", a.agentRolloutGet)
	a.bind("PUT /admin/agent-rollout", "admin", "agent_rollout_set", a.agentRolloutSet)
	a.bind("POST /admin/agent-rollout/pause", "admin", "agent_rollout_pause", a.agentRolloutPause(true))
	a.bind("POST /admin/agent-rollout/resume", "admin", "agent_rollout_resume", a.agentRolloutPause(false))
	a.bind("DELETE /admin/agent-rollout", "admin", "agent_rollout_clear", a.agentRolloutClear)
}

// agentUpdateOffer: 204 unless this host is in an active rollout. The record and signature go out byte for byte.
func (a *api) agentUpdateOffer(r *apiRequest) (response, error) {
	rollout, err := getRollout(r.Context(), a.store.pool)
	if err != nil {
		return response{}, err
	}
	if rollout == nil || rollout.Paused || !rollout.targets(r.Agent) {
		return response{status: 204}, nil
	}
	rel, err := loadPublishedRelease(agentReleasesDir(), rollout.Version)
	if err != nil {
		return response{}, err
	}
	return ok(object{"rollout_id": rollout.RolloutID, "release": string(rel.record), "signature": rel.signature}, nil)
}

// agentUpdateBinary serves a published release's binary while it still matches release.json (the agent checks the
// signed digest again).
func (a *api) agentUpdateBinary(r *apiRequest) (response, error) {
	rel, err := loadPublishedRelease(agentReleasesDir(), r.PathValue("version"))
	if err != nil {
		return response{}, err
	}
	b, found := rel.Binaries[r.PathValue("platform")]
	if !found {
		return response{}, failure(404, "agent release %s has no build for %s", rel.Version, r.PathValue("platform"))
	}
	data, err := os.ReadFile(filepath.Join(agentReleasesDir(), rel.Version, b.File))
	if err != nil {
		return response{}, failure(503, "agent release %s: %s is missing", rel.Version, b.File)
	}
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != b.SHA256 || int64(len(data)) != b.Size {
		return response{}, failure(503, "agent release %s: %s does not match release.json", rel.Version, b.File)
	}
	return response{status: 200, body: data, contentType: "application/octet-stream"}, nil
}

func (a *api) agentReleaseList(*apiRequest) (response, error) {
	releases, problems, err := listPublishedReleases(agentReleasesDir())
	if err != nil {
		return response{}, err
	}
	list := make([]object, 0, len(releases))
	for _, rel := range releases {
		list = append(list, object{"version": rel.Version, "sequence": rel.Sequence, "commit": rel.Commit,
			"published_at": rel.PublishedAt, "platforms": rel.Platforms})
	}
	return ok(object{"releases": list, "problems": orEmpty(problems)}, nil)
}

type agentHostStatus struct {
	Host            string   `json:"host" db:"host"`
	LastSeen        *float64 `json:"last_seen" db:"last_seen"`
	AgentVersion    string   `json:"agent_version" db:"agent_version"`
	ReportsUpdate   bool     `json:"-" db:"reports_update"` // false: the agent has no updater (or has not reported yet)
	State           string   `json:"state" db:"state"`
	TargetVersion   string   `json:"target_version" db:"target_version"`
	TargetSequence  int64    `json:"target_sequence" db:"target_sequence"`
	RolloutID       int64    `json:"rollout_id" db:"rollout_id"`
	RunningSequence int64    `json:"running_sequence" db:"running_sequence"`
	PreviousVersion string   `json:"previous_version" db:"previous_version"`
	Error           string   `json:"error" db:"error"`
	StateAt         *float64 `json:"state_at" db:"state_at"`
	ReportedAt      *float64 `json:"reported_at" db:"reported_at"`
	Targeted        bool     `json:"targeted"`
	Outcome         string   `json:"outcome"`
}

// Per-host outcomes for the current rollout.
const (
	outcomeNotTargeted   = "not_targeted"   // keeps its release
	outcomeOnTarget      = "on_target"      // runs the rollout's version
	outcomeWaiting       = "waiting"        // targeted; not started (next check, or the rollout is paused)
	outcomeInProgress    = "in_progress"    // downloading or confirming the new release
	outcomeFailed        = "failed"         // rolled back, refused or failed for this rollout: see error
	outcomeUpgradeNeeded = "upgrade_needed" // the agent has no updater: run the install command once
	outcomeDisabled      = "disabled"       // the agent's updater is off (no release key, --update off): see error
	outcomeUnknown       = "unknown"        // no heartbeat yet
)

func hostOutcome(h agentHostStatus, rollout *agentRollout) string {
	switch {
	case rollout == nil || !h.Targeted:
		return outcomeNotTargeted
	case h.LastSeen == nil:
		return outcomeUnknown
	case h.AgentVersion == rollout.Version && h.State != "confirming":
		return outcomeOnTarget
	case !h.ReportsUpdate:
		return outcomeUpgradeNeeded
	case h.State == "disabled":
		return outcomeDisabled
	case h.RolloutID == rollout.RolloutID && (h.State == "rolled_back" || h.State == "rejected" || h.State == "failed"):
		return outcomeFailed
	case h.RolloutID == rollout.RolloutID && (h.State == "downloading" || h.State == "confirming"):
		return outcomeInProgress
	}
	return outcomeWaiting
}

func (a *api) agentRolloutGet(r *apiRequest) (response, error) {
	ctx := r.Context()
	var rollout *agentRollout
	var hosts []agentHostStatus
	err := a.store.snapshot(ctx, func(tx pgx.Tx) error {
		var err error
		if rollout, err = getRollout(ctx, tx); err != nil {
			return err
		}
		hosts, err = rowsOf[agentHostStatus](ctx, tx, `SELECT h.name AS host, ag.last_seen,
			COALESCE(ag.agent_version, '') AS agent_version, s.host IS NOT NULL AS reports_update,
			COALESCE(s.state, '') AS state, COALESCE(s.target_version, '') AS target_version,
			COALESCE(s.target_sequence, 0) AS target_sequence, COALESCE(s.rollout_id, 0) AS rollout_id,
			COALESCE(s.running_sequence, 0) AS running_sequence, COALESCE(s.previous_version, '') AS previous_version,
			COALESCE(s.error, '') AS error, s.state_at, s.reported_at
			FROM hosts h LEFT JOIN agents ag ON ag.name = h.name LEFT JOIN agent_update_status s ON s.host = h.name
			ORDER BY h.name`)
		return err
	})
	if err != nil {
		return response{}, err
	}
	counts := map[string]int{}
	for i := range hosts {
		hosts[i].Targeted = rollout != nil && rollout.targets(hosts[i].Host)
		hosts[i].Outcome = hostOutcome(hosts[i], rollout)
		counts[hosts[i].Outcome]++
	}
	return ok(object{"rollout": rollout, "hosts": orEmpty(hosts), "summary": counts}, nil)
}

func (a *api) agentRolloutSet(r *apiRequest) (response, error) {
	var body struct {
		Version string          `json:"version"`
		Hosts   json.RawMessage `json:"hosts"`
		Paused  bool            `json:"paused"`
	}
	if err := r.decode(&body, "version", "hosts"); err != nil {
		return response{}, err
	}
	var hosts []string
	var all string
	if json.Unmarshal(body.Hosts, &all) == nil {
		if all != "all" {
			return response{}, failure(400, `hosts must be a list of host names or "all"`)
		}
	} else if err := json.Unmarshal(body.Hosts, &hosts); err != nil || len(hosts) == 0 {
		return response{}, failure(400, `hosts must be a non-empty list of host names or "all"`)
	}
	rel, err := loadPublishedRelease(agentReleasesDir(), body.Version)
	if err != nil {
		return response{}, err
	}
	ctx := r.Context()
	var rollout *agentRollout
	err = a.store.write(ctx, func(tx pgx.Tx) error {
		if hosts != nil {
			sort.Strings(hosts)
			hosts = slices.Compact(hosts)
			known, err := columnOf[string](ctx, tx, "SELECT name FROM hosts WHERE name = ANY($1)", hosts)
			if err != nil {
				return err
			}
			for _, h := range hosts {
				if !slices.Contains(known, h) {
					return failure(404, "not found: host %s", h)
				}
			}
		}
		_, err := tx.Exec(ctx, `INSERT INTO agent_rollout(id, rollout_id, version, sequence, hosts, paused, updated_at, updated_by)
			VALUES (1, nextval('agent_rollout_seq'), $1, $2, $3, $4, $5, $6)
			ON CONFLICT (id) DO UPDATE SET rollout_id = excluded.rollout_id, version = excluded.version,
			sequence = excluded.sequence, hosts = excluded.hosts, paused = excluded.paused,
			updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
			rel.Version, rel.Sequence, hosts, body.Paused, a.store.now(), r.Session.Admin)
		if err != nil {
			return err
		}
		rollout, err = getRollout(ctx, tx)
		return err
	})
	return ok(object{"rollout": rollout}, err)
}

func (a *api) agentRolloutPause(paused bool) endpoint {
	return func(r *apiRequest) (response, error) {
		ctx := r.Context()
		var rollout *agentRollout
		err := a.store.write(ctx, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, "UPDATE agent_rollout SET paused = $1, updated_at = $2, updated_by = $3 WHERE id = 1",
				paused, a.store.now(), r.Session.Admin)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				return failure(404, "no agent rollout")
			}
			rollout, err = getRollout(ctx, tx)
			return err
		})
		return ok(object{"rollout": rollout}, err)
	}
}

func (a *api) agentRolloutClear(r *apiRequest) (response, error) {
	ctx := r.Context()
	err := a.store.write(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "DELETE FROM agent_rollout WHERE id = 1")
		return err
	})
	return ok(object{"rollout": nil}, err)
}
