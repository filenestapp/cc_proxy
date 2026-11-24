package main

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

const (
	passwordIterations = 200_000
	sessionTTL         = 12 * 3600
	auditRetention     = 180 * 86400
	loginWindow        = 10 * time.Minute
	loginMaxFailures   = 10
)

func randomBytes(size int) []byte {
	value := make([]byte, size)
	rand.Read(value)
	return value
}

func randomToken(size int) string {
	return base64.RawURLEncoding.EncodeToString(randomBytes(size))
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func checkPasswordPolicy(password string) error {
	if utf8.RuneCountInString(password) < 8 {
		return failure(409, "password must be at least 8 characters")
	}
	return nil
}

func hashPassword(password string) string {
	return encodePassword(password, randomBytes(16))
}

func encodePassword(password string, salt []byte) string {
	digest, err := pbkdf2.Key(sha256.New, password, salt, passwordIterations, sha256.Size)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("pbkdf2_sha256$%d$%x$%x", passwordIterations, salt, digest)
}

var dummyPasswordHash = encodePassword("x", make([]byte, 16))

func checkPassword(password, stored string) bool {
	fields := strings.Split(stored, "$")
	if len(fields) != 4 || fields[0] != "pbkdf2_sha256" {
		return false
	}
	iterations, err := strconv.Atoi(fields[1])
	if err != nil || iterations < 1 {
		return false
	}
	salt, err := hex.DecodeString(fields[2])
	if err != nil {
		return false
	}
	digest, err := hex.DecodeString(fields[3])
	if err != nil || len(digest) != sha256.Size {
		return false
	}
	expected, err := pbkdf2.Key(sha256.New, password, salt, iterations, sha256.Size)
	return err == nil && hmac.Equal(expected, digest)
}

func wrongPassword() error {
	return failure(401, "wrong username or password")
}

func verifyLogin(password, hash string, err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		checkPassword(password, dummyPasswordHash)
		return wrongPassword()
	}
	if err != nil {
		return err
	}
	if !checkPassword(password, hash) {
		return wrongPassword()
	}
	return nil
}

type loginLimiter struct {
	mu        sync.Mutex
	failures  map[string][]time.Time
	lastSweep time.Time
}

func (l *loginLimiter) prune(key string, cutoff time.Time) []time.Time {
	hits := l.failures[key]
	i := 0
	for i < len(hits) && !hits[i].After(cutoff) {
		i++
	}
	if i == len(hits) {
		delete(l.failures, key)
		return nil
	}
	l.failures[key] = hits[i:]
	return hits[i:]
}

func (l *loginLimiter) blocked(now time.Time, keys ...string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-loginWindow)
	if l.lastSweep.Before(cutoff) {
		for key := range l.failures {
			l.prune(key, cutoff)
		}
		l.lastSweep = now
	}
	for _, key := range keys {
		if len(l.prune(key, cutoff)) >= loginMaxFailures {
			return true
		}
	}
	return false
}

func (l *loginLimiter) fail(now time.Time, keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, key := range keys {
		hits := l.prune(key, now.Add(-loginWindow))
		if len(hits) >= loginMaxFailures {
			hits = hits[len(hits)-loginMaxFailures+1:]
		}
		l.failures[key] = append(hits, now)
	}
}

func prepareAdmin(name, password string) (string, error) {
	if err := checkName("admin", name); err != nil {
		return "", err
	}
	if err := checkPasswordPolicy(password); err != nil {
		return "", err
	}
	return hashPassword(password), nil
}

func insertAdmin(ctx context.Context, db database, name, hash string, now float64) error {
	_, err := db.Exec(ctx, "INSERT INTO admins(name, password_hash, created_at) VALUES ($1,$2,$3)", name, hash, now)
	if uniqueViolation(err) {
		return failure(409, "admin %s exists", name)
	}
	return err
}

func (s *store) addAdmin(ctx context.Context, name, password string) error {
	hash, err := prepareAdmin(name, password)
	if err != nil {
		return err
	}
	return s.write(ctx, func(tx pgx.Tx) error {
		return insertAdmin(ctx, tx, name, hash, s.now())
	})
}

func (s *store) setAdminPassword(ctx context.Context, name, password string) error {
	if err := checkPasswordPolicy(password); err != nil {
		return err
	}
	pw := hashPassword(password)
	return s.write(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "UPDATE admins SET password_hash = $2 WHERE name = $1", name, pw)
		if err := rowsChanged(tag, err, "admin "+name); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "DELETE FROM admin_sessions WHERE admin = $1", name)
		return err
	})
}

func (s *store) deleteAdmin(ctx context.Context, name string) error {
	return s.write(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "DELETE FROM admins WHERE name = $1", name)
		if err := rowsChanged(tag, err, "admin "+name); err != nil {
			return err
		}
		var remaining bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM admins)").Scan(&remaining); err != nil {
			return err
		}
		if !remaining {
			return failure(409, "cannot delete the last admin")
		}
		return nil
	})
}

type adminView struct {
	Name      string   `json:"name"`
	CreatedAt float64  `json:"created_at"`
	LastLogin *float64 `json:"last_login"`
	Sessions  int      `json:"sessions"`
}

func (s *store) listAdmins(ctx context.Context) ([]adminView, error) {
	return rowsOf[adminView](ctx, s.pool, `SELECT a.name, a.created_at, a.last_login,
		(SELECT count(*) FROM admin_sessions WHERE admin = a.name AND expires_at > $1) AS sessions
		FROM admins a ORDER BY a.name`, s.now())
}

type adminSession struct {
	Admin     string
	CSRF      string
	ExpiresAt float64
}

func (s *store) loginAdmin(ctx context.Context, name, password, address string) (string, string, error) {
	var verified string
	err := s.pool.QueryRow(ctx, "SELECT password_hash FROM admins WHERE name = $1", name).Scan(&verified)
	if err := verifyLogin(password, verified, err); err != nil {
		return "", "", err
	}
	token, csrf := randomToken(32), randomToken(24)
	err = s.write(ctx, func(tx pgx.Tx) error {
		var current string
		err := tx.QueryRow(ctx, "SELECT password_hash FROM admins WHERE name = $1", name).Scan(&current)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && current != verified) {
			return wrongPassword()
		}
		if err != nil {
			return err
		}
		now := s.now()
		if _, err := tx.Exec(ctx, "DELETE FROM admin_sessions WHERE expires_at <= $1", now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO admin_sessions(token_hash, admin, csrf, created_at, expires_at, address)
			VALUES ($1,$2,$3,$4,$5,$6)`, hashToken(token), name, csrf, now, now+sessionTTL, address); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "UPDATE admins SET last_login = $2 WHERE name = $1", name, now)
		return err
	})
	return token, csrf, err
}

func (s *store) session(ctx context.Context, token string) (adminSession, error) {
	return rowOf[adminSession](ctx, s.pool,
		"SELECT admin, csrf, expires_at FROM admin_sessions WHERE token_hash = $1 AND expires_at > $2", hashToken(token), s.now())
}

func (s *store) logoutAdmin(ctx context.Context, token string) (string, error) {
	var name string
	err := s.pool.QueryRow(ctx, `DELETE FROM admin_sessions WHERE token_hash = $1 AND expires_at > $2 RETURNING admin`,
		hashToken(token), s.now()).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return name, err
}

func scrub(value any) any {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			sensitive := false
			for _, word := range []string{"password", "token", "secret", "private", "key"} {
				if strings.Contains(strings.ToLower(key), word) {
					sensitive = true
					break
				}
			}
			if sensitive {
				v[key] = "***"
			} else {
				v[key] = scrub(child)
			}
		}
	case []any:
		for i := range v {
			v[i] = scrub(v[i])
		}
	}
	return value
}

type auditEntry struct {
	ID      int64   `json:"id"`
	At      float64 `json:"at"`
	Actor   string  `json:"actor"`
	Action  string  `json:"action"`
	Target  string  `json:"target"`
	Detail  string  `json:"detail"`
	Address string  `json:"address"`
}

func (s *store) audit(ctx context.Context, actor, action, target, detail, address string) error {
	now := s.now()
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO audit(at, actor, action, target, detail, address) VALUES ($1,$2,$3,$4,$5,$6)`,
			now, actor, action, target, truncate(detail, 2000), address); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "DELETE FROM audit WHERE at < $1", now-auditRetention)
		return err
	})
}

func (s *store) auditLog(ctx context.Context, limit int, before *int64, actor string) ([]auditEntry, error) {
	return rowsOf[auditEntry](ctx, s.pool, `SELECT id, at, actor, action, target, detail, address FROM audit
		WHERE ($1::bigint IS NULL OR id < $1) AND ($2 = '' OR actor = $2) ORDER BY id DESC LIMIT $3`,
		before, actor, max(1, min(limit, 500)))
}
