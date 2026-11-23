package main

// XTCP transport for exit hosts behind NAT (frp).
//
// A host on the XTCP transport runs frpc next to sing-box. frpc registers one xtcp proxy with the frps rendezvous
// service (TLS on TCP 7003, verified against the configured CA, token authentication) and forwards to sing-box on
// 127.0.0.1:<local_port>. A visitor (the user's machine, also frpc) punches a direct UDP path to it. The proxy side
// has no relay option: frps only brokers the rendezvous, and a visitor without fallbackTo closes the connection when
// hole punching fails, so data never flows through frps.
//
//	GET    /admin/hosts/{name}/xtcp     settings, without the auth token or secret key
//	PUT    /admin/hosts/{name}/xtcp     enable or change; auth_token and secret_key are kept when omitted on change.
//	                                    A secret_key generated here (omitted on enable) is returned once, for the
//	                                    visitor configuration.
//	DELETE /admin/hosts/{name}/xtcp     back to the public-entry transport
//	GET    /install/xtcp/frpc.toml      (host agent token) rendered frpc configuration, or 204 for a public-entry host
//	GET    /install/xtcp/ca.pem         (host agent token) the CA that verifies frps, or 204
//
// Credentials live only in this table and, on the exit host, in root/SYSTEM-only files the installer writes.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const xtcpTableSQL = `CREATE TABLE IF NOT EXISTS host_xtcp (
    host text COLLATE "C" PRIMARY KEY REFERENCES hosts(name) ON DELETE CASCADE,
    server_addr text NOT NULL,
    server_port integer NOT NULL CHECK (server_port BETWEEN 1 AND 65535),
    tls_server_name text NOT NULL,
    ca_pem text NOT NULL,
    auth_token text NOT NULL,
    proxy_name text NOT NULL UNIQUE,
    secret_key text NOT NULL,
    local_port integer NOT NULL CHECK (local_port BETWEEN 1 AND 65535),
    updated_at double precision NOT NULL
)`

func ensureXTCPTable(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, xtcpTableSQL)
	return err
}

const defaultFrpsPort = 7003

var (
	xtcpHostPattern   = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	xtcpSecretPattern = regexp.MustCompile(`^[A-Za-z0-9_.~+/=-]{16,256}$`)
	xtcpNamePattern   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	// Paths the installer asks for; they go into TOML literal strings, so no quote or newline can appear.
	xtcpPathPattern = regexp.MustCompile(`^(/|[A-Za-z]:\\)[A-Za-z0-9 _.@+\\/:-]{0,400}$`)
)

type xtcpSettings struct {
	Host          string  `db:"host"`
	ServerAddr    string  `db:"server_addr"`
	ServerPort    int     `db:"server_port"`
	TLSServerName string  `db:"tls_server_name"`
	CAPEM         string  `db:"ca_pem"`
	AuthToken     string  `db:"auth_token"`
	ProxyName     string  `db:"proxy_name"`
	SecretKey     string  `db:"secret_key"`
	LocalPort     int     `db:"local_port"`
	UpdatedAt     float64 `db:"updated_at"`
}

func getXTCP(ctx context.Context, db database, hostName string) (xtcpSettings, bool, error) {
	x, err := rowOf[xtcpSettings](ctx, db, `SELECT host, server_addr, server_port, tls_server_name, ca_pem,
		auth_token, proxy_name, secret_key, local_port, updated_at FROM host_xtcp WHERE host = $1`, hostName)
	if errors.Is(err, pgx.ErrNoRows) {
		return x, false, nil
	}
	return x, err == nil, err
}

// normalizeCA accepts one or more PEM CA certificates and returns them re-encoded.
func normalizeCA(text string) (string, *x509.Certificate, error) {
	if len(text) > 64<<10 {
		return "", nil, failure(400, "ca_pem is too large")
	}
	var out strings.Builder
	var first *x509.Certificate
	rest := []byte(text)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return "", nil, failure(400, "ca_pem may contain certificates only")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", nil, failure(400, "ca_pem: %v", err)
		}
		if !cert.IsCA {
			return "", nil, failure(400, "ca_pem: %s is not a CA certificate", cert.Subject)
		}
		if first == nil {
			first = cert
		}
		pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})
	}
	if first == nil || strings.TrimSpace(string(rest)) != "" {
		return "", nil, failure(400, "ca_pem must be PEM-encoded CA certificates")
	}
	return out.String(), first, nil
}

func newXTCPSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

type xtcpRequest struct {
	ServerAddr    *string  `json:"server_addr"`
	ServerPort    *integer `json:"server_port"`
	TLSServerName *string  `json:"tls_server_name"`
	CAPEM         *string  `json:"ca_pem"`
	AuthToken     *string  `json:"auth_token"`
	ProxyName     *string  `json:"proxy_name"`
	SecretKey     *string  `json:"secret_key"`
	LocalPort     *integer `json:"local_port"`
}

// putXTCP enables or changes the XTCP settings of a host. It returns a secret key it generated (else "").
func (s *store) putXTCP(ctx context.Context, hostName string, req xtcpRequest) (string, error) {
	generated := ""
	err := s.mutate(ctx, func(tx pgx.Tx) error {
		h, err := getHost(ctx, tx, hostName)
		if err != nil {
			return err
		}
		x, exists, err := getXTCP(ctx, tx, hostName)
		if err != nil {
			return err
		}
		if !exists {
			x = xtcpSettings{Host: hostName, ServerPort: defaultFrpsPort, ProxyName: "ccproxy-" + hostName + "-direct"}
		}
		set := func(dst *string, src *string) {
			if src != nil {
				*dst = strings.TrimSpace(*src)
			}
		}
		set(&x.ServerAddr, req.ServerAddr)
		set(&x.TLSServerName, req.TLSServerName)
		set(&x.ProxyName, req.ProxyName)
		set(&x.AuthToken, req.AuthToken)
		set(&x.SecretKey, req.SecretKey)
		if req.ServerPort != nil {
			x.ServerPort = int(*req.ServerPort)
		}
		if req.LocalPort != nil {
			x.LocalPort = int(*req.LocalPort)
		}
		if req.CAPEM != nil {
			if x.CAPEM, _, err = normalizeCA(*req.CAPEM); err != nil {
				return err
			}
		}
		if x.TLSServerName == "" {
			x.TLSServerName = x.ServerAddr
		}
		if x.SecretKey == "" && !exists {
			x.SecretKey = newXTCPSecret()
			generated = x.SecretKey
		}
		switch {
		case !xtcpHostPattern.MatchString(x.ServerAddr):
			return failure(400, "server_addr must be the frps host name or IPv4 address")
		case x.ServerPort < 1 || x.ServerPort > 65535:
			return failure(400, "server_port must be 1-65535")
		case !xtcpHostPattern.MatchString(x.TLSServerName):
			return failure(400, "tls_server_name must be the name in the frps certificate")
		case x.CAPEM == "":
			return failure(400, "ca_pem is required: frps certificates are always verified")
		case !xtcpSecretPattern.MatchString(x.AuthToken):
			return failure(400, "auth_token is required: 16-256 characters of A-Z a-z 0-9 _ . ~ + / = -")
		case !xtcpSecretPattern.MatchString(x.SecretKey):
			return failure(400, "secret_key must be 16-256 characters of A-Z a-z 0-9 _ . ~ + / = -")
		case !xtcpNamePattern.MatchString(x.ProxyName):
			return failure(400, "proxy_name must be 1-64 characters of A-Z a-z 0-9 _ . -")
		case x.LocalPort < h.PortMin || x.LocalPort > h.PortMax:
			return failure(400, "local_port must be the user entry port sing-box listens on, within %d-%d", h.PortMin, h.PortMax)
		}
		var other string
		err = tx.QueryRow(ctx, "SELECT host FROM host_xtcp WHERE proxy_name = $1 AND host <> $2", x.ProxyName, hostName).Scan(&other)
		if err == nil {
			return failure(409, "proxy_name %s is already used by host %s", x.ProxyName, other)
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO host_xtcp(host, server_addr, server_port, tls_server_name, ca_pem, auth_token,
			proxy_name, secret_key, local_port, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (host) DO UPDATE SET server_addr = excluded.server_addr, server_port = excluded.server_port,
			tls_server_name = excluded.tls_server_name, ca_pem = excluded.ca_pem, auth_token = excluded.auth_token,
			proxy_name = excluded.proxy_name, secret_key = excluded.secret_key, local_port = excluded.local_port,
			updated_at = excluded.updated_at`,
			hostName, x.ServerAddr, x.ServerPort, x.TLSServerName, x.CAPEM, x.AuthToken, x.ProxyName, x.SecretKey,
			x.LocalPort, s.now())
		return err
	})
	if err != nil {
		return "", err
	}
	return generated, nil
}

func (s *store) deleteXTCP(ctx context.Context, hostName string) error {
	return s.mutate(ctx, func(tx pgx.Tx) error {
		if _, err := getHost(ctx, tx, hostName); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "DELETE FROM host_xtcp WHERE host = $1", hostName)
		return err
	})
}

// xtcpView is what an administrator sees: never the auth token or the secret key.
func xtcpView(x xtcpSettings) object {
	view := object{"transport": "xtcp", "server_addr": x.ServerAddr, "server_port": x.ServerPort,
		"tls_server_name": x.TLSServerName, "proxy_name": x.ProxyName, "local_port": x.LocalPort,
		"has_auth_token": x.AuthToken != "", "has_secret_key": x.SecretKey != "", "updated_at": x.UpdatedAt}
	if _, cert, err := normalizeCA(x.CAPEM); err == nil {
		sum := sha256.Sum256(cert.Raw)
		view["ca_subject"] = cert.Subject.String()
		view["ca_not_after"] = cert.NotAfter.UTC().Format(time.RFC3339)
		view["ca_sha256"] = hex.EncodeToString(sum[:])
	}
	return view
}

// renderFrpcTOML is the exit host's frpc configuration: one xtcp proxy, TLS verified against caFile, token auth.
// It has no fallback or relay setting; values are validated, so the basic strings need no escaping.
func renderFrpcTOML(x xtcpSettings, caFile, logFile string) string {
	logTo := `"console"`
	logExtra := ""
	if logFile != "" {
		logTo = "'" + logFile + "'"
		logExtra = "log.maxDays = 7\n"
	}
	return fmt.Sprintf(`# frpc for CC Proxy exit host %[1]s, written by the installer from the control plane.
# XTCP only: the exit host and the visitor connect directly; frps on %[2]s:%[3]d only brokers the
# rendezvous. There is no relay fallback: when hole punching fails, the visitor's connection is closed.
serverAddr = "%[2]s"
serverPort = %[3]d
loginFailExit = false

auth.method = "token"
auth.token = "%[4]s"

transport.tls.enable = true
transport.tls.trustedCaFile = '%[5]s'
transport.tls.serverName = "%[6]s"

log.to = %[7]s
log.level = "info"
%[8]s
[[proxies]]
name = "%[9]s"
type = "xtcp"
secretKey = "%[10]s"
localIP = "127.0.0.1"
localPort = %[11]d
`, x.Host, x.ServerAddr, x.ServerPort, x.AuthToken, caFile, x.TLSServerName, logTo, logExtra, x.ProxyName,
		x.SecretKey, x.LocalPort)
}

func (a *api) xtcpRoutes() {
	a.bind("GET /admin/hosts/{name}/xtcp", "admin", "", a.xtcpGet)
	a.bind("PUT /admin/hosts/{name}/xtcp", "admin", "xtcp_update", a.xtcpPut)
	a.bind("DELETE /admin/hosts/{name}/xtcp", "admin", "xtcp_disable", a.xtcpDelete)
	a.bind("GET /install/xtcp/frpc.toml", "agent", "", a.xtcpFrpcConfig)
	a.bind("GET /install/xtcp/ca.pem", "agent", "", a.xtcpCA)
}

func (a *api) xtcpGet(r *apiRequest) (response, error) {
	name := r.PathValue("name")
	if _, err := getHost(r.Context(), a.store.pool, name); err != nil {
		return response{}, err
	}
	x, ok, err := getXTCP(r.Context(), a.store.pool, name)
	if err != nil {
		return response{}, err
	}
	if !ok {
		return response{status: 200, body: object{"transport": "public"}}, nil
	}
	return response{status: 200, body: xtcpView(x)}, nil
}

func (a *api) xtcpPut(r *apiRequest) (response, error) {
	var req xtcpRequest
	if err := r.decode(&req); err != nil {
		return response{}, err
	}
	name := r.PathValue("name")
	generated, err := a.store.putXTCP(r.Context(), name, req)
	if err != nil {
		return response{}, err
	}
	x, _, err := getXTCP(r.Context(), a.store.pool, name)
	view := xtcpView(x)
	if generated != "" {
		view["secret_key"] = generated // shown once: the visitor needs the same key
	}
	return response{status: 200, body: view}, err
}

func (a *api) xtcpDelete(r *apiRequest) (response, error) {
	name := r.PathValue("name")
	return ok(object{"host": name, "transport": "public"}, a.store.deleteXTCP(r.Context(), name))
}

var noContent = response{status: 204, body: []byte{}, contentType: "text/plain; charset=utf-8"}

// xtcpFrpcConfig serves the calling host's own frpc configuration (identified by its agent token).
func (a *api) xtcpFrpcConfig(r *apiRequest) (response, error) {
	x, ok, err := getXTCP(r.Context(), a.store.pool, r.Agent)
	if err != nil || !ok {
		return noContent, err
	}
	q := r.URL.Query()
	caFile, logFile := q.Get("ca_file"), q.Get("log_file")
	if !xtcpPathPattern.MatchString(caFile) || (logFile != "" && !xtcpPathPattern.MatchString(logFile)) {
		return response{}, failure(400, "ca_file (and log_file) must be absolute paths without quotes")
	}
	return response{status: 200, body: []byte(renderFrpcTOML(x, caFile, logFile)), contentType: "text/plain; charset=utf-8"}, nil
}

func (a *api) xtcpCA(r *apiRequest) (response, error) {
	x, ok, err := getXTCP(r.Context(), a.store.pool, r.Agent)
	if err != nil || !ok {
		return noContent, err
	}
	return response{status: 200, body: []byte(x.CAPEM), contentType: "application/x-pem-file"}, nil
}
