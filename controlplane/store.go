package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schemaSQL string

const (
	defaultCooldown = 7 * 86400
	maxDevices      = 5
	schemaVersion   = 1
)

type database interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

type store struct {
	pool  *pgxpool.Pool
	clock func() time.Time
}

func openStore(ctx context.Context, dsn string) (*store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		// The connection parser may include the full DSN in errors.
		return nil, errors.New("invalid PostgreSQL connection configuration")
	}
	s := &store{pool: pool, clock: time.Now}
	if err := s.initializeSchema(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("initialize PostgreSQL: %w", err)
	}
	return s, nil
}

func (s *store) initializeSchema(ctx context.Context) error {
	return s.write(ctx, func(tx pgx.Tx) error {
		var hasSettings bool
		if err := tx.QueryRow(ctx, "SELECT to_regclass(format('%I.settings', current_schema())) IS NOT NULL").Scan(&hasSettings); err != nil {
			return err
		}
		if !hasSettings {
			if _, err := tx.Exec(ctx, schemaSQL); err != nil {
				return err
			}
			if err := ensureUsageTables(ctx, tx); err != nil {
				return err
			}
			if err := ensureXTCPTable(ctx, tx); err != nil {
				return err
			}
			return ensureCustomerTables(ctx, tx)
		}
		var version int
		if err := tx.QueryRow(ctx, "SELECT value::integer FROM settings WHERE key = 'schema'").Scan(&version); err != nil {
			return fmt.Errorf("read PostgreSQL schema version: %w", err)
		}
		if version != schemaVersion {
			return fmt.Errorf("unsupported PostgreSQL schema version %d", version)
		}
		// This additive change lets the previous binary still serve the database on rollback.
		var hasObservedIPv4 bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name = 'hosts'
			AND column_name = 'observed_public_ipv4')`).Scan(&hasObservedIPv4); err != nil {
			return err
		}
		if !hasObservedIPv4 {
			if _, err := tx.Exec(ctx, `ALTER TABLE hosts ADD COLUMN IF NOT EXISTS observed_public_ipv4 inet
				CHECK (family(observed_public_ipv4) = 4 AND masklen(observed_public_ipv4) = 32)`); err != nil {
				return err
			}
		}
		// Additive as well: a previous binary ignores the table, so rollback keeps working.
		if err := ensureUsageTables(ctx, tx); err != nil {
			return err
		}
		if err := ensureXTCPTable(ctx, tx); err != nil {
			return err
		}
		return ensureCustomerTables(ctx, tx)
	})
}

func (s *store) now() float64 {
	return float64(s.clock().UnixMicro()) / 1e6
}

// Serialize configuration and account mutations across all control plane processes in this schema.
func (s *store) write(ctx context.Context, change func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(67143001, hashtext(current_schema()))"); err != nil {
			return err
		}
		return change(tx)
	})
}

func (s *store) mutate(ctx context.Context, change func(pgx.Tx) error) error {
	return s.write(ctx, func(tx pgx.Tx) error {
		if err := change(tx); err != nil {
			return err
		}
		return bumpVersion(ctx, tx)
	})
}

// Render from a single committed snapshot so an atomic move never looks like a partial assignment.
func (s *store) snapshot(ctx context.Context, read func(pgx.Tx) error) error {
	return pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly,
	}, read)
}

func bumpVersion(ctx context.Context, db database) error {
	_, err := db.Exec(ctx, `INSERT INTO settings(key, value) VALUES ('version', '1')
		ON CONFLICT (key) DO UPDATE SET value = to_jsonb(settings.value::bigint + 1)`)
	return err
}

func version(ctx context.Context, db database) (int64, error) {
	var v int64
	err := db.QueryRow(ctx, `SELECT COALESCE((SELECT value::bigint FROM settings WHERE key = 'version'), 0)`).Scan(&v)
	return v, err
}

func rowsOf[T any](ctx context.Context, db database, query string, args ...any) ([]T, error) {
	rows, err := db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByNameLax[T])
}

func rowOf[T any](ctx context.Context, db database, query string, args ...any) (T, error) {
	var zero T
	rows, err := db.Query(ctx, query, args...)
	if err != nil {
		return zero, err
	}
	return pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[T])
}

func missing(err error, label string) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return failure(404, "not found: %s", label)
	}
	return err
}

func uniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func rowsChanged(tag pgconn.CommandTag, err error, label string) error {
	if err == nil && tag.RowsAffected() == 0 {
		return missing(pgx.ErrNoRows, label)
	}
	return err
}

type settings struct {
	ClientPolicy json.RawMessage `db:"client_policy" json:"client_policy"`
	Cooldown     int64           `db:"cooldown_seconds" json:"cooldown_seconds"`
	Monitor      json.RawMessage `json:"monitor"`
	Alerts       json.RawMessage `json:"alerts"`
}

func loadSettings(ctx context.Context, db database) (settings, error) {
	return rowOf[settings](ctx, db, `SELECT
		COALESCE((SELECT value FROM settings WHERE key = 'client_policy'), '{}') AS client_policy,
		COALESCE((SELECT value::bigint FROM settings WHERE key = 'cooldown_seconds'), $1) AS cooldown_seconds,
		COALESCE((SELECT value FROM settings WHERE key = 'monitor'), '{"egress_targets":[],"entries":[]}') AS monitor,
		COALESCE((SELECT value FROM settings WHERE key = 'alerts'), '{}') AS alerts`, defaultCooldown)
}

func settingsPatch(body fields) (map[string]any, error) {
	values := make(map[string]any)
	for _, key := range []string{"client_policy", "cooldown_seconds", "monitor", "alerts"} {
		raw := body[key]
		if len(raw) == 0 || string(raw) == "null" {
			continue
		}
		switch key {
		case "cooldown_seconds":
			var seconds integer
			if err := json.Unmarshal(raw, &seconds); err != nil {
				return nil, failure(400, "cooldown_seconds must be an integer")
			}
			values[key] = int(seconds)
			continue
		case "client_policy":
			var policy fields
			if err := json.Unmarshal(raw, &policy); err != nil {
				return nil, failure(409, "client_policy must be an object")
			}
			if suffixes, ok := policy["domain_suffix"]; ok {
				var domains []string
				if err := json.Unmarshal(suffixes, &domains); err != nil {
					return nil, failure(400, "proxied domains must be a list of domains or HTTP(S) URLs")
				}
				domains, err := normalizeProxiedDomains(domains)
				if err != nil {
					return nil, err
				}
				policy["domain_suffix"], err = json.Marshal(domains)
				if err != nil {
					return nil, err
				}
				values[key] = policy
				continue
			}
		case "monitor":
			var monitor monitorSettings
			if err := json.Unmarshal(raw, &monitor); err != nil {
				return nil, failure(409, "monitor must be an object with list fields egress_targets and entries")
			}
			var obj fields
			if err := json.Unmarshal(raw, &obj); err != nil {
				return nil, err
			}
			if slices.ContainsFunc([]string{"egress_targets", "entries"}, func(k string) bool { return string(obj[k]) == "null" }) {
				return nil, failure(409, "monitor fields egress_targets and entries must be lists")
			}
		case "alerts":
			if _, err := parseAlertSettings(raw); err != nil {
				return nil, failure(409, "%s", err)
			}
		}
		values[key] = raw
	}
	return values, nil
}

func setSettings(ctx context.Context, db database, values map[string]any) error {
	for key, value := range values {
		if _, err := db.Exec(ctx, `INSERT INTO settings(key, value) VALUES ($1, $2)
			ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, value); err != nil {
			return err
		}
	}
	return nil
}
