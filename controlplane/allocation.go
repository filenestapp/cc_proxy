package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"

	"github.com/jackc/pgx/v5"
)

type host struct {
	Name, PublicHost, ServerName, HandshakeServer string
	PortMin, PortMax, HandshakePort               int
	BlockPrivate                                  bool
	BlockCIDRs                                    []string
	RealityPrivate, RealityPublic, ShortID        string
}

type hostOptions struct {
	PublicHost      *string   `json:"public_host"`
	ServerName      *string   `json:"server_name"`
	HandshakeServer *string   `json:"handshake_server"`
	HandshakePort   *integer  `json:"handshake_port"`
	PortMin         *integer  `json:"port_min"`
	PortMax         *integer  `json:"port_max"`
	BlockPrivate    *bool     `json:"block_private"`
	BlockCIDRs      *[]string `json:"block_cidrs"`
}

func (o hostOptions) apply(h *host) error {
	if o.PublicHost != nil {
		h.PublicHost = *o.PublicHost
	}
	if o.ServerName != nil {
		h.ServerName = *o.ServerName
	}
	if o.HandshakeServer != nil {
		h.HandshakeServer = *o.HandshakeServer
	}
	if h.HandshakeServer == "" {
		h.HandshakeServer = h.ServerName
	}
	if o.HandshakePort != nil {
		h.HandshakePort = int(*o.HandshakePort)
	}
	if o.PortMin != nil {
		h.PortMin = int(*o.PortMin)
	}
	if o.PortMax != nil {
		h.PortMax = int(*o.PortMax)
	}
	if o.BlockPrivate != nil {
		h.BlockPrivate = *o.BlockPrivate
	}
	if o.BlockCIDRs != nil {
		h.BlockCIDRs = *o.BlockCIDRs
	}
	switch {
	case h.PublicHost == "":
		return failure(409, "public_host is required")
	case h.ServerName == "":
		return failure(409, "server_name (the Reality camouflage SNI) is required")
	case h.PortMin < 1 || h.PortMax < h.PortMin || h.PortMax > 65535:
		return failure(409, "port range must satisfy 1 <= port_min <= port_max <= 65535")
	case h.HandshakePort < 1 || h.HandshakePort > 65535:
		return failure(409, "handshake_port must be between 1 and 65535")
	}
	return nil
}

func getHost(ctx context.Context, db database, name string) (host, error) {
	h, err := rowOf[host](ctx, db, `SELECT name, public_host, port_min, port_max, reality_private,
		reality_public, short_id, server_name, handshake_server, handshake_port, block_private, block_cidrs
		FROM hosts WHERE name = $1`, name)
	return h, missing(err, "host "+name)
}

func (s *store) addHost(ctx context.Context, name string, options hostOptions) (string, error) {
	if err := checkName("host", name); err != nil {
		return "", err
	}
	h := host{PortMin: 20000, PortMax: 29999, HandshakePort: 443, BlockPrivate: true, BlockCIDRs: []string{"169.254.169.254/32"}}
	if err := options.apply(&h); err != nil {
		return "", err
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	token := randomToken(32)
	err = s.mutate(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO hosts(name, public_host, port_min, port_max, reality_private, reality_public,
			short_id, server_name, handshake_server, handshake_port, block_private, block_cidrs, agent_token_hash, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, name, h.PublicHost, h.PortMin, h.PortMax,
			base64.RawURLEncoding.EncodeToString(key.Bytes()), base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()),
			hex.EncodeToString(randomBytes(8)), h.ServerName, h.HandshakeServer, h.HandshakePort, h.BlockPrivate,
			h.BlockCIDRs, hashToken(token), s.now())
		if uniqueViolation(err) {
			return failure(409, "host %s exists", name)
		}
		return err
	})
	return token, err
}

func (s *store) updateHost(ctx context.Context, name string, options hostOptions) error {
	return s.mutate(ctx, func(tx pgx.Tx) error {
		h, err := getHost(ctx, tx, name)
		if err != nil {
			return err
		}
		if err := options.apply(&h); err != nil {
			return err
		}
		outside, err := rowsOf[struct{ Binding string }](ctx, tx, `SELECT name || ':' || port AS binding
			FROM users WHERE host = $1 AND port NOT BETWEEN $2 AND $3 ORDER BY name`, name, h.PortMin, h.PortMax)
		if err != nil {
			return err
		}
		if len(outside) != 0 {
			bindings := make([]string, 0, len(outside))
			for _, row := range outside {
				bindings = append(bindings, row.Binding)
			}
			return failure(409, "users outside the new port range: %s", strings.Join(bindings, ", "))
		}
		_, err = tx.Exec(ctx, `UPDATE hosts SET public_host=$2, port_min=$3, port_max=$4, server_name=$5,
			handshake_server=$6, handshake_port=$7, block_private=$8, block_cidrs=$9 WHERE name=$1`,
			name, h.PublicHost, h.PortMin, h.PortMax, h.ServerName, h.HandshakeServer, h.HandshakePort, h.BlockPrivate, h.BlockCIDRs)
		return err
	})
}

func (s *store) rotateAgentToken(ctx context.Context, name string) (string, error) {
	token := randomToken(32)
	return token, s.mutate(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "UPDATE hosts SET agent_token_hash = $2 WHERE name = $1", name, hashToken(token))
		return rowsChanged(tag, err, "host "+name)
	})
}

func (s *store) deleteHost(ctx context.Context, name string) error {
	return s.mutate(ctx, func(tx pgx.Tx) error {
		holders, err := columnOf[string](ctx, tx, "SELECT name FROM users WHERE host = $1 ORDER BY name", name)
		if err != nil {
			return err
		}
		if len(holders) != 0 {
			return failure(409, "host %s still serves users: %s", name, strings.Join(holders, ", "))
		}
		if _, err := tx.Exec(ctx, "DELETE FROM egress_ips WHERE host = $1", name); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, "DELETE FROM hosts WHERE name = $1", name)
		return rowsChanged(tag, err, "host "+name)
	})
}

type hostView struct {
	Name          string `json:"name"`
	PublicHost    string `json:"public_host"`
	PortRange     []int  `json:"port_range"`
	ServerName    string `json:"server_name"`
	RealityPublic string `json:"reality_public_key"`
	IPs           int    `json:"ips"`
	Users         int    `json:"users"`
}

func listHosts(ctx context.Context, db database) ([]hostView, error) {
	return rowsOf[hostView](ctx, db, `SELECT h.name, h.public_host, ARRAY[h.port_min, h.port_max] AS port_range,
		h.server_name, h.reality_public, (SELECT count(*) FROM egress_ips e WHERE e.host = h.name) AS ips,
		(SELECT count(*) FROM users u WHERE u.host = h.name) AS users FROM hosts h ORDER BY h.name`)
}

func columnOf[T any](ctx context.Context, db database, query string, args ...any) ([]T, error) {
	rows, err := db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[T])
}

func ipv4(value string) (string, error) {
	addr, err := netip.ParseAddr(value)
	if err != nil || !addr.Is4() {
		return "", failure(400, "%q is not an IPv4 address", value)
	}
	return addr.String(), nil
}

func (s *store) addIPs(ctx context.Context, hostName string, ips []string) ([]string, error) {
	added := make([]string, 0, len(ips))
	err := s.mutate(ctx, func(tx pgx.Tx) error {
		if _, err := getHost(ctx, tx, hostName); err != nil {
			return err
		}
		for _, value := range ips {
			ip, err := ipv4(value)
			if err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, `INSERT INTO egress_ips(ip, host) VALUES ($1::text::inet, $2) ON CONFLICT (ip) DO NOTHING`,
				ip, hostName)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 0 {
				added = append(added, ip)
				continue
			}
			var owner string
			if err := tx.QueryRow(ctx, "SELECT host FROM egress_ips WHERE ip = $1::text::inet", ip).Scan(&owner); err != nil {
				return err
			}
			if owner != hostName {
				return failure(409, "ip %s already belongs to host %s", ip, owner)
			}
		}
		return nil
	})
	return added, err
}

type ipView struct {
	IP            string         `json:"ip"`
	Host          string         `json:"host"`
	Status        string         `json:"status"`
	Users         []string       `json:"users"`
	Ports         map[string]int `json:"ports"`
	CooldownUntil *float64       `json:"cooldown_until"`
	Note          string         `json:"note"`
}

func listIPs(ctx context.Context, db database, hostName string, now float64) ([]ipView, error) {
	return rowsOf[ipView](ctx, db, `SELECT host(e.ip) AS ip, e.host, e.note, NULLIF(e.cooldown_until, 0) AS cooldown_until,
		CASE WHEN count(u.name) > 0 THEN 'assigned' WHEN e.banned THEN 'banned'
			WHEN e.cooldown_until > $2 THEN 'cooldown' ELSE 'available' END AS status,
		COALESCE(array_agg(u.name ORDER BY u.name) FILTER (WHERE u.name IS NOT NULL), '{}') AS users,
		COALESCE(jsonb_object_agg(u.name, u.port) FILTER (WHERE u.name IS NOT NULL), '{}') AS ports
		FROM egress_ips e LEFT JOIN users u ON u.egress_ip = e.ip
		WHERE $1 = '' OR e.host = $1 GROUP BY e.ip ORDER BY e.ip`, hostName, now)
}

func (s *store) banIP(ctx context.Context, ip, note string) ([]string, error) {
	if _, err := ipv4(ip); err != nil {
		return nil, err
	}
	var released []string
	err := s.mutate(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "UPDATE egress_ips SET banned = true, note = $2 WHERE ip = $1::text::inet", ip, note)
		if err := rowsChanged(tag, err, "ip "+ip); err != nil {
			return err
		}
		released, err = columnOf[string](ctx, tx, `UPDATE users SET egress_ip = NULL, host = NULL, port = NULL
			WHERE egress_ip = $1::text::inet RETURNING name`, ip)
		return err
	})
	return released, err
}

func (s *store) deleteIP(ctx context.Context, ip string) error {
	if _, err := ipv4(ip); err != nil {
		return err
	}
	return s.mutate(ctx, func(tx pgx.Tx) error {
		holders, err := columnOf[string](ctx, tx, "SELECT name FROM users WHERE egress_ip = $1::text::inet ORDER BY name", ip)
		if err != nil {
			return err
		}
		if len(holders) != 0 {
			return failure(409, "ip %s is held by %s; release it first", ip, strings.Join(holders, ", "))
		}
		tag, err := tx.Exec(ctx, "DELETE FROM egress_ips WHERE ip = $1::text::inet", ip)
		return rowsChanged(tag, err, "ip "+ip)
	})
}

func (s *store) makeAvailable(ctx context.Context, ip string) error {
	if _, err := ipv4(ip); err != nil {
		return err
	}
	return s.mutate(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "UPDATE egress_ips SET banned = false, cooldown_until = 0 WHERE ip = $1::text::inet", ip)
		return rowsChanged(tag, err, "ip "+ip)
	})
}

type assignment struct {
	IP   *string  `json:"ip"`
	Port *integer `json:"port"`
	Host string   `json:"host"`
}

func (s *store) assign(ctx context.Context, name string, req assignment, moving bool) (userSummary, error) {
	var summary userSummary
	err := s.write(ctx, func(tx pgx.Tx) error {
		user, err := getUser(ctx, tx, name)
		if err != nil {
			return err
		}
		if moving && user.IP == nil {
			return failure(409, "user %s holds no egress IP; use assign", name)
		}
		if !moving && user.IP != nil {
			return failure(409, "user %s already holds %s:%d; use reassign to move it", name, *user.IP, *user.Port)
		}
		ip, h, port, err := s.chooseBinding(ctx, tx, user, req)
		if err != nil {
			return err
		}
		summary = userSummary{User: name, EgressIP: &ip, Host: h.Name, Entry: &entryAddress{Host: h.PublicHost, Port: port}}
		if user.IP != nil && *user.IP == ip && *user.Port == port {
			return nil
		}
		if _, err := tx.Exec(ctx, "UPDATE users SET egress_ip = $2::text::inet, host = $3, port = $4 WHERE name = $1",
			name, ip, h.Name, port); err != nil {
			return err
		}
		if user.IP != nil && *user.IP != ip {
			if err := s.coolIfFree(ctx, tx, *user.IP); err != nil {
				return err
			}
		}
		return bumpVersion(ctx, tx)
	})
	return summary, err
}

func (s *store) chooseBinding(ctx context.Context, db database, user userRow, req assignment) (string, host, int, error) {
	var ip string
	if req.IP == nil {
		if req.Host != "" {
			if _, err := getHost(ctx, db, req.Host); err != nil {
				return "", host{}, 0, err
			}
		}
		err := db.QueryRow(ctx, `SELECT host(e.ip) FROM egress_ips e
			WHERE ($1 = '' OR e.host = $1) AND NOT e.banned AND e.cooldown_until <= $2
				AND e.ip IS DISTINCT FROM $3::text::inet
				AND NOT EXISTS (SELECT 1 FROM users WHERE egress_ip = e.ip)
			ORDER BY e.ip LIMIT 1`, req.Host, s.now(), user.IP).Scan(&ip)
		if errors.Is(err, pgx.ErrNoRows) {
			if req.Host != "" {
				return "", host{}, 0, failure(409, "no free egress IP on host %s", req.Host)
			}
			return "", host{}, 0, failure(409, "no free egress IP")
		}
		if err != nil {
			return "", host{}, 0, err
		}
	} else {
		var err error
		ip, err = ipv4(*req.IP)
		if err != nil {
			return "", host{}, 0, err
		}
	}
	var hostName string
	var banned bool
	var cooldown float64
	err := db.QueryRow(ctx, "SELECT host, banned, cooldown_until FROM egress_ips WHERE ip = $1::text::inet", ip).
		Scan(&hostName, &banned, &cooldown)
	if err != nil {
		return "", host{}, 0, missing(err, "ip "+ip)
	}
	if req.Host != "" && hostName != req.Host {
		return "", host{}, 0, failure(409, "ip %s belongs to host %s, not %s", ip, hostName, req.Host)
	}
	if banned {
		return "", host{}, 0, failure(409, "ip %s is banned", ip)
	}
	holders, err := rowsOf[struct{ Name, Mode string }](ctx, db,
		"SELECT name, mode FROM users WHERE egress_ip = $1::text::inet AND name != $2 ORDER BY name", ip, user.Name)
	if err != nil {
		return "", host{}, 0, err
	}
	if len(holders) == 0 && (user.IP == nil || *user.IP != ip) && cooldown > s.now() {
		return "", host{}, 0, failure(409, "ip %s is cooldown", ip)
	}
	for _, holder := range holders {
		if user.Mode != "shared" || holder.Mode != "shared" {
			names := make([]string, 0, len(holders))
			for _, h := range holders {
				names = append(names, h.Name)
			}
			return "", host{}, 0, failure(409, "ip %s is held by %s; sharing needs mode=shared on every holder",
				ip, strings.Join(names, ", "))
		}
	}
	h, err := getHost(ctx, db, hostName)
	if err != nil {
		return "", host{}, 0, err
	}
	port, err := choosePort(ctx, db, h, user, req.Port)
	return ip, h, port, err
}

func choosePort(ctx context.Context, db database, h host, user userRow, requested *integer) (int, error) {
	if requested == nil && user.Host != nil && *user.Host == h.Name {
		return *user.Port, nil
	}
	rows, err := rowsOf[struct {
		Name string
		Port int
	}](ctx, db, "SELECT name, port FROM users WHERE host = $1 AND name != $2", h.Name, user.Name)
	if err != nil {
		return 0, err
	}
	used := make(map[int]string, len(rows))
	for _, row := range rows {
		used[row.Port] = row.Name
	}
	if requested != nil {
		port := int(*requested)
		if port < h.PortMin || port > h.PortMax {
			return 0, failure(409, "port %d is outside host %s's range %d-%d", port, h.Name, h.PortMin, h.PortMax)
		}
		if holder, ok := used[port]; ok {
			return 0, failure(409, "port %d on host %s is used by %s", port, h.Name, holder)
		}
		return port, nil
	}
	for port := h.PortMin; port <= h.PortMax; port++ {
		if _, ok := used[port]; !ok {
			return port, nil
		}
	}
	return 0, failure(409, "no free port left in %d-%d on host %s", h.PortMin, h.PortMax, h.Name)
}

func (s *store) releaseBinding(ctx context.Context, db database, user userRow) error {
	if user.IP == nil {
		return nil
	}
	if _, err := db.Exec(ctx, "UPDATE users SET egress_ip = NULL, host = NULL, port = NULL WHERE name = $1", user.Name); err != nil {
		return err
	}
	return s.coolIfFree(ctx, db, *user.IP)
}

func (s *store) coolIfFree(ctx context.Context, db database, ip string) error {
	_, err := db.Exec(ctx, `UPDATE egress_ips SET cooldown_until = $2::double precision +
		COALESCE((SELECT value::bigint FROM settings WHERE key = 'cooldown_seconds'), $3::bigint)
		WHERE ip = $1::text::inet AND NOT EXISTS(SELECT 1 FROM users WHERE egress_ip = egress_ips.ip)`, ip, s.now(), defaultCooldown)
	return err
}
