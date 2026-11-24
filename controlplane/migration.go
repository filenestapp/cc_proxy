package main

import (
	"bufio"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

//go:embed sqlite_export.py
var sqliteExport string

var importTables = []string{"settings", "hosts", "egress_ips", "users", "devices", "admins", "admin_sessions", "customers", "customer_sessions", "email_tokens", "audit", "agents", "probes", "alerts"}

func (s *store) migrateSQLite(ctx context.Context, path string) error {
	var imported []string
	err := s.write(ctx, func(tx pgx.Tx) error {
		for _, table := range importTables {
			query := "SELECT EXISTS(SELECT 1 FROM " + pgx.Identifier{table}.Sanitize()
			if table == "settings" {
				query += " WHERE key != 'schema'"
			}
			var populated bool
			if err := tx.QueryRow(ctx, query+")").Scan(&populated); err != nil {
				return err
			}
			if populated {
				return errors.New("target PostgreSQL control plane database is not empty")
			}
		}
		var err error
		imported, err = copySQLite(ctx, tx, path)
		if err != nil {
			return err
		}
		for _, table := range []string{"devices", "audit", "probes", "alerts"} {
			identifier := pgx.Identifier{table}.Sanitize()
			var next int64
			if err := tx.QueryRow(ctx, "SELECT GREATEST(COALESCE(max(id), 0) + 1, 1) FROM "+identifier).Scan(&next); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, fmt.Sprintf("ALTER TABLE %s ALTER COLUMN id RESTART WITH %d", identifier, next)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("SQLite migration failed: %w", err)
	}
	fmt.Println("Imported " + strings.Join(imported, ", "))
	return nil
}

func copySQLite(ctx context.Context, tx pgx.Tx, path string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "python3", "-c", sqliteExport, path)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start SQLite reader (requires Python 3): %w", err)
	}
	imported, err := copyTables(ctx, tx, bufio.NewReader(stdout))
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return nil, err
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("read SQLite v2 snapshot: %w", err)
	}
	return imported, nil
}

func copyTables(ctx context.Context, tx pgx.Tx, source *bufio.Reader) ([]string, error) {
	var imported []string
	lastTable := -1
	for {
		header, err := source.ReadString('\n')
		if errors.Is(err, io.EOF) && header == "" {
			return imported, nil
		}
		if err != nil {
			return nil, fmt.Errorf("read SQLite table header: %w", err)
		}
		fields := strings.Fields(header)
		if len(fields) < 2 {
			return nil, errors.New("invalid SQLite table header")
		}
		table := fields[0]
		index := slices.Index(importTables, table)
		if index <= lastTable {
			return nil, errors.New("unexpected SQLite table in export")
		}
		lastTable = index
		quoted := make([]string, 0, len(fields)-1)
		for _, column := range fields[1:] {
			quoted = append(quoted, pgx.Identifier{column}.Sanitize())
		}
		query := "COPY " + pgx.Identifier{table}.Sanitize() + " (" + strings.Join(quoted, ", ") + ") FROM STDIN"
		input := &sqliteCopyInput{source: source}
		tag, err := tx.Conn().PgConn().CopyFrom(ctx, input, query)
		if err != nil {
			// PostgreSQL COPY details can include password hashes, tokens, or private keys.
			return nil, fmt.Errorf("copy SQLite table %s into PostgreSQL: %s", table, copyErrorMessage(err))
		}
		imported = append(imported, fmt.Sprintf("%d %s", tag.RowsAffected(), table))
	}
}

type sqliteCopyInput struct {
	source  *bufio.Reader
	pending []byte
}

func (r *sqliteCopyInput) Read(p []byte) (int, error) {
	if len(r.pending) == 0 {
		line, err := r.source.ReadBytes('\n')
		if errors.Is(err, io.EOF) {
			return 0, io.ErrUnexpectedEOF
		}
		if err != nil {
			return 0, err
		}
		if string(line) == "\\.\n" {
			return 0, io.EOF
		}
		r.pending = line
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

func copyErrorMessage(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return "PostgreSQL rejected the row data (SQLSTATE " + pgErr.Code + ")"
	}
	return err.Error()
}
