package main

// The desktop app's XTCP visitor (issue #61).
//
//	GET /v1/xtcp-visitor   (device token) the calling device's own visitor settings, or 204 when its user's exit host
//	                       uses the public entry. ETag / If-None-Match as for /v1/config.
//
// The response carries what the app needs to run frpc as a visitor for its user's mapping only: the frps address and
// TLS name, the frps CA, the frps token every exit host and visitor share (decided in #61: frp 0.72.0 has no per-user
// token), the mapping's proxy name and scoped secret key, and the local port sing-box dials. It never carries
// mapping_secret, the host's own secret key for another user's mapping, or anything about another host. The app
// renders the frpc configuration itself, so local file paths never reach the server.
//
// exit_state is the mapping's sync state on the exit host (xtcp_sync.go): ready, pending, failed or upgrade_needed.
// It lets the app tell "the exit host is not ready" apart from a hole-punching failure.
//
// The rendered sing-box client configuration (/v1/config) is unchanged: on an XTCP host its server is the public
// entry address, which must therefore be 127.0.0.1, where the visitor listens. A host configured otherwise gets 409
// here instead of a visitor that sing-box would never reach.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
)

const xtcpVisitorBindAddr = "127.0.0.1"

type deviceVisitor struct {
	ServerAddr    string `json:"server_addr"`
	ServerPort    int    `json:"server_port"`
	TLSServerName string `json:"tls_server_name"`
	CAPEM         string `json:"ca_pem"`
	AuthToken     string `json:"auth_token"`
	ProxyName     string `json:"proxy_name"`
	SecretKey     string `json:"secret_key"`
	BindAddr      string `json:"bind_addr"`
	BindPort      int    `json:"bind_port"`
	ExitState     string `json:"exit_state"`
}

func (a *api) deviceXTCPVisitor(r *apiRequest) (response, error) {
	ctx := r.Context()
	var v *deviceVisitor
	err := a.store.snapshot(ctx, func(tx pgx.Tx) error {
		var hostName *string
		var port *int
		var entry string
		err := tx.QueryRow(ctx, `SELECT u.host, u.port, COALESCE(`+publicEntryHostSQL+`, '')
			FROM devices d JOIN users u ON u.name = d.user_name LEFT JOIN hosts h ON h.name = u.host
			WHERE d.token_hash = $1 AND d.revoked_at IS NULL`, r.Device.TokenHash).Scan(&hostName, &port, &entry)
		if errors.Is(err, pgx.ErrNoRows) {
			return failure(401, "unauthorized")
		}
		if err != nil {
			return err
		}
		if hostName == nil || port == nil {
			return failure(409, "no exit IP is assigned to %s yet; ask the admin", r.Device.User)
		}
		x, found, err := getXTCP(ctx, tx, *hostName)
		if err != nil || !found {
			return err
		}
		if entry != xtcpVisitorBindAddr {
			return failure(409, "your exit host uses XTCP, but its public entry address is not %s; ask the admin to set it",
				xtcpVisitorBindAddr)
		}
		mappings, err := xtcpMappings(ctx, tx, x)
		if err != nil {
			return err
		}
		view := object{}
		if err := xtcpSyncView(ctx, tx, x, mappings, view); err != nil {
			return err
		}
		for i, m := range mappings {
			if m.User != r.Device.User {
				continue
			}
			state := xtcpSyncPending
			if rows, ok := view["mappings"].([]object); ok && i < len(rows) {
				state, _ = rows[i]["status"].(string)
			}
			v = &deviceVisitor{ServerAddr: x.ServerAddr, ServerPort: x.ServerPort, TLSServerName: x.TLSServerName,
				CAPEM: x.CAPEM, AuthToken: x.AuthToken, ProxyName: m.ProxyName, SecretKey: m.secretKey,
				BindAddr: xtcpVisitorBindAddr, BindPort: m.Port, ExitState: state}
			return nil
		}
		return failure(409, "your exit IP has no XTCP mapping yet; ask the admin")
	})
	if err != nil || v == nil {
		return noContent, err
	}
	body, err := json.Marshal(v)
	if err != nil {
		return response{}, err
	}
	sum := sha256.Sum256(body)
	return configResponse(r, renderedConfig{Body: body, ETag: "visitor-" + hex.EncodeToString(sum[:16])}), nil
}
