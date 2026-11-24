package main

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

type userRow struct {
	Name, Mode, PasswordHash string
	IP, Host                 *string
	Port                     *int
	MaxDevices               int
}

func getUser(ctx context.Context, db database, name string) (userRow, error) {
	u, err := rowOf[userRow](ctx, db, `SELECT name, mode, password_hash, host(egress_ip) AS ip, host, port, max_devices
		FROM users WHERE name = $1`, name)
	return u, missing(err, "user "+name)
}

type entryAddress struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type userSummary struct {
	User     string        `json:"user"`
	EgressIP *string       `json:"egress_ip"`
	Host     string        `json:"host,omitempty"`
	Entry    *entryAddress `json:"entry"`
}

func userInfo(ctx context.Context, db database, name string) (userSummary, error) {
	var u userSummary
	var host, publicHost *string
	var port *int
	err := db.QueryRow(ctx, `SELECT u.name, host(u.egress_ip), u.host, `+publicEntryHostSQL+`, u.port
		FROM users u LEFT JOIN hosts h ON h.name = u.host WHERE u.name = $1`, name).
		Scan(&u.User, &u.EgressIP, &host, &publicHost, &port)
	if err == nil && host != nil {
		u.Host = *host
		if *publicHost != "" {
			u.Entry = &entryAddress{Host: *publicHost, Port: *port}
		}
	}
	return u, missing(err, "user "+name)
}

func validDeviceLimit(limit int) error {
	if limit < 1 || limit > 2147483647 {
		return failure(409, "max_devices must be between 1 and 2147483647")
	}
	return nil
}

func (s *store) addUser(ctx context.Context, name, password, mode string, limit int) error {
	if err := checkName("user", name); err != nil {
		return err
	}
	if err := checkPasswordPolicy(password); err != nil {
		return err
	}
	if mode != "exclusive" && mode != "shared" {
		return failure(409, "mode must be exclusive or shared")
	}
	if err := validDeviceLimit(limit); err != nil {
		return err
	}
	pw := hashPassword(password)
	return s.mutate(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO users(name, password_hash, mode, max_devices, created_at) VALUES ($1,$2,$3,$4,$5)",
			name, pw, mode, limit, s.now())
		if uniqueViolation(err) {
			return failure(409, "user %s exists", name)
		}
		return err
	})
}

func (s *store) setUserPassword(ctx context.Context, name, password string, revoke bool) error {
	if err := checkPasswordPolicy(password); err != nil {
		return err
	}
	pw := hashPassword(password)
	return s.mutate(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "UPDATE users SET password_hash = $2 WHERE name = $1", name, pw)
		if err := rowsChanged(tag, err, "user "+name); err != nil {
			return err
		}
		if revoke {
			_, err = tx.Exec(ctx, "UPDATE devices SET revoked_at = $2 WHERE user_name = $1 AND revoked_at IS NULL", name, s.now())
		}
		return err
	})
}

type userUpdate struct {
	MaxDevices *int
	Mode       *string
}

// updateUser changes the device limit and/or the egress mode in one transaction. Switching to shared keeps the
// current IP, port, and device credentials. Switching to exclusive is refused, without any change, while another
// user holds the same egress IP.
func (s *store) updateUser(ctx context.Context, name string, change userUpdate) error {
	if change.MaxDevices != nil {
		if err := validDeviceLimit(*change.MaxDevices); err != nil {
			return err
		}
	}
	if change.Mode != nil && *change.Mode != "exclusive" && *change.Mode != "shared" {
		return failure(409, "mode must be exclusive or shared")
	}
	return s.mutate(ctx, func(tx pgx.Tx) error {
		user, err := getUser(ctx, tx, name)
		if err != nil {
			return err
		}
		if change.Mode != nil && *change.Mode == "exclusive" && user.Mode != "exclusive" && user.IP != nil {
			others, err := columnOf[string](ctx, tx, `SELECT name FROM users WHERE egress_ip = $1::text::inet AND name != $2
				ORDER BY name`, *user.IP, name)
			if err != nil {
				return err
			}
			if len(others) != 0 {
				return failure(409, "user %s shares %s with %s; move or release the other holders before switching to exclusive",
					name, *user.IP, strings.Join(others, ", "))
			}
		}
		if change.MaxDevices != nil {
			if _, err := tx.Exec(ctx, "UPDATE users SET max_devices = $2 WHERE name = $1", name, *change.MaxDevices); err != nil {
				return err
			}
		}
		if change.Mode != nil {
			if _, err := tx.Exec(ctx, "UPDATE users SET mode = $2 WHERE name = $1", name, *change.Mode); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *store) deleteUser(ctx context.Context, name string) error {
	return s.mutate(ctx, func(tx pgx.Tx) error {
		user, err := getUser(ctx, tx, name)
		if err != nil {
			return err
		}
		if err := s.releaseBinding(ctx, tx, user); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "DELETE FROM users WHERE name = $1", name)
		return err
	})
}

func (s *store) releaseUser(ctx context.Context, name string) (string, error) {
	var ip string
	err := s.mutate(ctx, func(tx pgx.Tx) error {
		user, err := getUser(ctx, tx, name)
		if err != nil {
			return err
		}
		if user.IP == nil {
			return failure(409, "user %s holds no egress IP", name)
		}
		ip = *user.IP
		return s.releaseBinding(ctx, tx, user)
	})
	return ip, err
}

type deviceView struct {
	User     string   `db:"user_name" json:"-"`
	Name     string   `json:"name"`
	Platform string   `json:"platform"`
	Revoked  bool     `json:"revoked"`
	LastSeen *float64 `json:"last_seen"`
}

type userView struct {
	Name       string       `json:"name"`
	Mode       string       `json:"mode"`
	EgressIP   *string      `json:"egress_ip"`
	Host       *string      `json:"host"`
	Port       *int         `json:"port"`
	MaxDevices int          `json:"max_devices"`
	Devices    []deviceView `db:"-" json:"devices"`
}

func listUsers(ctx context.Context, db database) ([]userView, error) {
	users, err := rowsOf[userView](ctx, db, `SELECT name, mode, host(egress_ip) AS egress_ip, host, port, max_devices
		FROM users ORDER BY name`)
	if err != nil {
		return nil, err
	}
	devices, err := rowsOf[deviceView](ctx, db, `SELECT user_name, name, platform, revoked_at IS NOT NULL AS revoked, last_seen
		FROM devices ORDER BY name`)
	if err != nil {
		return nil, err
	}
	byUser := make(map[string][]deviceView)
	for _, d := range devices {
		byUser[d.User] = append(byUser[d.User], d)
	}
	for i := range users {
		users[i].Devices = orEmpty(byUser[users[i].Name])
	}
	return users, nil
}

func orEmpty[T any](values []T) []T {
	if values == nil {
		return []T{}
	}
	return values
}

func (s *store) loginUser(ctx context.Context, name, password, device, platform string) (string, userSummary, error) {
	var verified string
	err := s.pool.QueryRow(ctx, "SELECT password_hash FROM users WHERE name = $1", name).Scan(&verified)
	if err := verifyLogin(password, verified, err); err != nil {
		return "", userSummary{}, err
	}
	token := randomToken(32)
	var summary userSummary
	err = s.mutate(ctx, func(tx pgx.Tx) error {
		u, err := getUser(ctx, tx, name)
		if err != nil && statusOf(err) != 404 {
			return err
		}
		if u.PasswordHash != verified {
			return wrongPassword()
		}
		if err := s.putDevice(ctx, tx, u, device, truncate(platform, 32), token); err != nil {
			return err
		}
		summary, err = userInfo(ctx, tx, name)
		return err
	})
	return token, summary, err
}

func (s *store) addDevice(ctx context.Context, name, device, platform string) (string, error) {
	token := randomToken(32)
	return token, s.mutate(ctx, func(tx pgx.Tx) error {
		u, err := getUser(ctx, tx, name)
		if err != nil {
			return err
		}
		return s.putDevice(ctx, tx, u, device, platform, token)
	})
}

func (s *store) putDevice(ctx context.Context, tx pgx.Tx, u userRow, device, platform, token string) error {
	if err := checkName("device", device); err != nil {
		return err
	}
	now := s.now()
	tag, err := tx.Exec(ctx, `UPDATE devices SET token_hash = $3, platform = $4, last_seen = $5
		WHERE user_name = $1 AND name = $2 AND revoked_at IS NULL`, u.Name, device, hashToken(token), platform, now)
	if err != nil || tag.RowsAffected() != 0 {
		return err
	}
	var active int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM devices WHERE user_name = $1 AND revoked_at IS NULL", u.Name).Scan(&active); err != nil {
		return err
	}
	if active >= u.MaxDevices {
		return failure(409, "device limit reached (%d); sign out on another device or ask the admin", u.MaxDevices)
	}
	_, err = tx.Exec(ctx, `INSERT INTO devices(user_name, name, platform, token_hash, created_at, last_seen)
		VALUES ($1,$2,$3,$4,$5,$5) ON CONFLICT (user_name, name) DO UPDATE SET platform = excluded.platform,
		token_hash = excluded.token_hash, uuid = excluded.uuid, created_at = excluded.created_at,
		last_seen = excluded.last_seen, revoked_at = NULL`, u.Name, device, platform, hashToken(token), now)
	return err
}

func (s *store) revokeDevice(ctx context.Context, user, device string) error {
	return s.mutate(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE devices SET revoked_at = $3 WHERE user_name = $1 AND name = $2 AND revoked_at IS NULL`,
			user, device, s.now())
		return rowsChanged(tag, err, "active device "+device+" of "+user)
	})
}

type deviceIdentity struct {
	User, Name, TokenHash string
}

func (s *store) identifyDevice(ctx context.Context, token string) (deviceIdentity, error) {
	d := deviceIdentity{TokenHash: hashToken(token)}
	err := s.pool.QueryRow(ctx, `UPDATE devices SET last_seen = $2 WHERE token_hash = $1 AND revoked_at IS NULL
		RETURNING user_name, name`, d.TokenHash, s.now()).Scan(&d.User, &d.Name)
	if errors.Is(err, pgx.ErrNoRows) {
		return d, failure(401, "unauthorized")
	}
	return d, err
}

func (s *store) logoutDevice(ctx context.Context, d deviceIdentity) error {
	return s.mutate(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "UPDATE devices SET revoked_at = $2 WHERE token_hash = $1 AND revoked_at IS NULL", d.TokenHash, s.now())
		if err == nil && tag.RowsAffected() == 0 {
			return failure(401, "unauthorized")
		}
		return err
	})
}

func truncate(value string, size int) string {
	for i := range value {
		if size == 0 {
			return value[:i]
		}
		size--
	}
	return value
}

func checkName(kind, name string) error {
	if name == "" || utf8.RuneCountInString(name) > 64 || containsInvalidNameRune(name) {
		return failure(409, "%s name must be 1-64 characters without '/' or spaces", kind)
	}
	return nil
}

func containsInvalidNameRune(name string) bool {
	for _, c := range name {
		switch c {
		case '/', ' ', '\t', '\n', '\x00':
			return true
		}
	}
	return false
}
