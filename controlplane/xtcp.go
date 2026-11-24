package main

// XTCP transport for exit hosts behind NAT (frp).
//
// A host on the XTCP transport runs frpc next to sing-box. frpc registers xtcp proxies with the frps rendezvous
// service (TLS on TCP 7003, verified against the configured CA, token authentication) and forwards each to sing-box
// on 127.0.0.1:<entry port>. A visitor (the user's machine, also frpc) punches a direct UDP path to it. The proxy
// side has no relay option: frps only brokers the rendezvous, and a visitor without fallbackTo closes the connection
// when hole punching fails, so data never flows through frps.
//
// Mappings. The configured proxy_name and secret_key forward to local_port: this primary mapping is rendered
// exactly as before, so an existing single-port visitor keeps working. Every other user assigned to the host gets
// its own proxy, <proxy_name>-<entry port>, forwarding to that user's entry port. Its secret key is derived from
// mapping_secret, the proxy name, and the user name. mapping_secret is a random server-held key, independent of the
// primary visitor's secret_key: it never leaves the control plane (no admin view, visitor, or exit-host response
// carries it), so holding any visitor key, including the primary one, grants no other mapping. It is generated once
// per host and persisted, so derived keys stay stable across restarts. A user who leaves the port invalidates the
// derived key.
//
//	GET    /admin/hosts/{name}/xtcp     settings, without the auth token or secret key
//	PUT    /admin/hosts/{name}/xtcp     enable or change; auth_token and secret_key are kept when omitted on change.
//	                                    A secret_key generated here (omitted on enable) is returned once, for the
//	                                    visitor configuration.
//	DELETE /admin/hosts/{name}/xtcp     back to the public-entry transport
//	GET    /install/xtcp/frpc.toml      (host agent token) rendered frpc configuration, or 204 for a public-entry host
//	GET    /install/xtcp/ca.pem         (host agent token) the CA that verifies frps, or 204
//	GET    /admin/users/{name}/xtcp-visitor  the visitor configuration for one user's mapping (scoped secret key;
//	                                    the frps token stays write-only and is read from FRP_AUTH_TOKEN)
//
// Credentials live only in this table and, on the exit host, in root/SYSTEM-only files the installer writes.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strconv"
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

// The delivery columns are additive, so a previous binary still reads and writes the table on rollback.
const xtcpDeliverySQL = `ALTER TABLE host_xtcp ADD COLUMN IF NOT EXISTS delivered_sha256 text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS delivered_at double precision`

// mapping_secret is additive too. A previous binary leaves it at its default, and the next start fills it in.
const xtcpMappingSecretSQL = `ALTER TABLE host_xtcp ADD COLUMN IF NOT EXISTS mapping_secret text NOT NULL DEFAULT ''`

func ensureXTCPTable(ctx context.Context, tx pgx.Tx) error {
	for _, statement := range []string{xtcpTableSQL, xtcpDeliverySQL, xtcpMappingSecretSQL} {
		if _, err := tx.Exec(ctx, statement); err != nil {
			return err
		}
	}
	// Existing XTCP hosts (single-port, before per-user mappings) get their own random derivation secret. The
	// primary secret_key and its visitor are left as they are.
	hosts, err := columnOf[string](ctx, tx, "SELECT host FROM host_xtcp WHERE mapping_secret = '' ORDER BY host")
	if err != nil {
		return err
	}
	for _, host := range hosts {
		if _, err := tx.Exec(ctx, "UPDATE host_xtcp SET mapping_secret = $2 WHERE host = $1 AND mapping_secret = ''",
			host, newXTCPSecret()); err != nil {
			return err
		}
	}
	return nil
}

const defaultFrpsPort = 7003

var (
	xtcpHostPattern   = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	xtcpSecretPattern = regexp.MustCompile(`^[A-Za-z0-9_.~+/=-]{16,256}$`)
	xtcpNamePattern   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	// Paths the installer asks for; they go into TOML literal strings, so no quote or newline can appear.
	xtcpPathPattern = regexp.MustCompile(`^(/|[A-Za-z]:\\)[A-Za-z0-9 _.@+\\/:-]{0,400}$`)
	// The visitor's CA path may be relative to frpc's working directory.
	xtcpVisitorCAPattern = regexp.MustCompile(`^[A-Za-z0-9 _.@+\\/:~-]{1,400}$`)
)

type xtcpSettings struct {
	Host          string `db:"host"`
	ServerAddr    string `db:"server_addr"`
	ServerPort    int    `db:"server_port"`
	TLSServerName string `db:"tls_server_name"`
	CAPEM         string `db:"ca_pem"`
	AuthToken     string `db:"auth_token"`
	ProxyName     string `db:"proxy_name"`
	SecretKey     string `db:"secret_key"`
	// Server-only key that derives the visitor keys of the non-primary mappings. Never serialized.
	MappingSecret string  `db:"mapping_secret"`
	LocalPort     int     `db:"local_port"`
	UpdatedAt     float64 `db:"updated_at"`
	// Fingerprint of the frpc configuration last served to the host's installer, and when.
	DeliveredSHA256 string   `db:"delivered_sha256"`
	DeliveredAt     *float64 `db:"delivered_at"`
}

func getXTCP(ctx context.Context, db database, hostName string) (xtcpSettings, bool, error) {
	x, err := rowOf[xtcpSettings](ctx, db, `SELECT host, server_addr, server_port, tls_server_name, ca_pem,
		auth_token, proxy_name, secret_key, mapping_secret, local_port, updated_at, delivered_sha256, delivered_at
		FROM host_xtcp WHERE host = $1`, hostName)
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
		if x.MappingSecret == "" { // kept once set, so derived visitor keys survive settings changes
			x.MappingSecret = newXTCPSecret()
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
		others, err := rowsOf[struct{ Host, ProxyName string }](ctx, tx,
			"SELECT host, proxy_name FROM host_xtcp WHERE host <> $1 ORDER BY host", hostName)
		if err != nil {
			return err
		}
		for _, other := range others {
			if proxyNamesOverlap(x.ProxyName, other.ProxyName) {
				return failure(409, "proxy_name %s overlaps the proxy names of host %s (%s and %s-<port>)",
					x.ProxyName, other.Host, other.ProxyName, other.ProxyName)
			}
		}
		_, err = tx.Exec(ctx, `INSERT INTO host_xtcp(host, server_addr, server_port, tls_server_name, ca_pem, auth_token,
			proxy_name, secret_key, mapping_secret, local_port, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			ON CONFLICT (host) DO UPDATE SET server_addr = excluded.server_addr, server_port = excluded.server_port,
			tls_server_name = excluded.tls_server_name, ca_pem = excluded.ca_pem, auth_token = excluded.auth_token,
			proxy_name = excluded.proxy_name, secret_key = excluded.secret_key, mapping_secret = excluded.mapping_secret,
			local_port = excluded.local_port, updated_at = excluded.updated_at`,
			hostName, x.ServerAddr, x.ServerPort, x.TLSServerName, x.CAPEM, x.AuthToken, x.ProxyName, x.SecretKey,
			x.MappingSecret, x.LocalPort, s.now())
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

// proxyNamesOverlap reports whether two hosts' proxy names could produce the same frps proxy name, given that each
// host also registers <proxy_name>-<port> for its additional users.
func proxyNamesOverlap(a, b string) bool {
	derivedFrom := func(name, base string) bool {
		port, ok := strings.CutPrefix(name, base+"-")
		if !ok || port == "" {
			return false
		}
		_, err := strconv.ParseUint(port, 10, 16)
		return err == nil
	}
	return a == b || derivedFrom(a, b) || derivedFrom(b, a)
}

// xtcpMapping is one frpc xtcp proxy: a user's entry port, reachable through its own proxy name and secret key.
type xtcpMapping struct {
	User      string `json:"user"` // empty when nobody holds the primary port
	Port      int    `json:"port"`
	ProxyName string `json:"proxy_name"`
	Primary   bool   `json:"primary"`
	secretKey string
}

func userProxyName(base string, port int) string {
	return base + "-" + strconv.Itoa(port)
}

// userSecretKey is the visitor secret for one user's mapping, derived from the host's server-only mapping secret.
// It is bound to the proxy name and the user, so it opens no other proxy and changes when a different user takes
// over the port.
func userSecretKey(mappingSecret, proxyName, user string) string {
	mac := hmac.New(sha256.New, []byte(mappingSecret))
	mac.Write([]byte("ccproxy xtcp visitor\x00" + proxyName + "\x00" + user))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// xtcpMappings lists the primary mapping first and then one mapping per other user assigned to the host, by port.
func xtcpMappings(ctx context.Context, db database, x xtcpSettings) ([]xtcpMapping, error) {
	users, err := rowsOf[struct {
		Name string
		Port int
	}](ctx, db, "SELECT name, port FROM users WHERE host = $1 ORDER BY port", x.Host)
	if err != nil {
		return nil, err
	}
	mappings := []xtcpMapping{{Port: x.LocalPort, ProxyName: x.ProxyName, Primary: true, secretKey: x.SecretKey}}
	for _, u := range users {
		if u.Port == x.LocalPort {
			mappings[0].User = u.Name
			continue
		}
		// Fail closed rather than fall back to the primary visitor's key (a row a previous binary wrote).
		if x.MappingSecret == "" {
			return nil, failure(409, "XTCP host %s has no mapping secret yet; restart the control plane or save its XTCP settings", x.Host)
		}
		name := userProxyName(x.ProxyName, u.Port)
		mappings = append(mappings, xtcpMapping{User: u.Name, Port: u.Port, ProxyName: name,
			secretKey: userSecretKey(x.MappingSecret, name, u.Name)})
	}
	return mappings, nil
}

// xtcpFingerprint identifies what the exit host needs: the rendered proxies and the CA. Installer paths are left out.
func xtcpFingerprint(x xtcpSettings, mappings []xtcpMapping) string {
	sum := sha256.Sum256([]byte(renderFrpcTOML(x, mappings, "", "") + "\x00" + x.CAPEM))
	return hex.EncodeToString(sum[:])
}

// renderFrpcTOML is the exit host's frpc configuration: one xtcp proxy per mapping, TLS verified against caFile,
// token auth. It has no fallback or relay setting; values are validated, so the basic strings need no escaping.
// The first mapping is the primary one and renders exactly as the single-port configuration did.
func renderFrpcTOML(x xtcpSettings, mappings []xtcpMapping, caFile, logFile string) string {
	logTo := `"console"`
	logExtra := ""
	if logFile != "" {
		logTo = "'" + logFile + "'"
		logExtra = "log.maxDays = 7\n"
	}
	var out strings.Builder
	fmt.Fprintf(&out, `# frpc for aifree exit host %[1]s, written by the installer from the control plane.
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
%[8]s`, x.Host, x.ServerAddr, x.ServerPort, x.AuthToken, caFile, x.TLSServerName, logTo, logExtra)
	for _, m := range mappings {
		fmt.Fprintf(&out, `
[[proxies]]
name = "%s"
type = "xtcp"
secretKey = "%s"
localIP = "127.0.0.1"
localPort = %d
`, m.ProxyName, m.secretKey, m.Port)
	}
	return out.String()
}

// renderVisitorTOML is one user's frpc visitor. It carries only that mapping's secret key. The frps token is not
// stored in it: frpc reads it from the FRP_AUTH_TOKEN environment variable through its template support. Because
// frpc renders the file as a Go template, free-form names (users, hosts) stay out of it.
func renderVisitorTOML(x xtcpSettings, m xtcpMapping, bindAddr, caFile string) string {
	return fmt.Sprintf(`# frpc XTCP visitor for one aifree user. Point aifree at %[1]s:%[2]d.
# Direct connections only: there is no relay fallback.
# Set FRP_AUTH_TOKEN to the frps token in frpc's environment, and save the frps CA as %[3]s.
serverAddr = "%[4]s"
serverPort = %[5]d
auth.method = "token"
auth.token = "{{ .Envs.FRP_AUTH_TOKEN }}"
transport.tls.enable = true
transport.tls.trustedCaFile = '%[3]s'
transport.tls.serverName = "%[6]s"

[[visitors]]
name = "%[7]s-visitor"
type = "xtcp"
serverName = "%[7]s"
secretKey = "%[8]s"
bindAddr = "%[1]s"
bindPort = %[2]d
protocol = "quic"
`, bindAddr, m.Port, caFile, x.ServerAddr, x.ServerPort, x.TLSServerName, m.ProxyName, m.secretKey)
}

func (a *api) xtcpRoutes() {
	a.bind("GET /admin/hosts/{name}/xtcp", "admin", "", a.xtcpGet)
	a.bind("PUT /admin/hosts/{name}/xtcp", "admin", "xtcp_update", a.xtcpPut)
	a.bind("DELETE /admin/hosts/{name}/xtcp", "admin", "xtcp_disable", a.xtcpDelete)
	a.bind("GET /install/xtcp/frpc.toml", "agent", "", a.xtcpFrpcConfig)
	a.bind("GET /install/xtcp/ca.pem", "agent", "", a.xtcpCA)
	a.bind("GET /admin/users/{name}/xtcp-visitor", "admin", "", a.xtcpVisitor)
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
	view, err := xtcpFullView(r.Context(), a.store.pool, x)
	return response{status: 200, body: view}, err
}

// xtcpFullView adds the mappings (without secrets) and whether the host's installer has fetched the current
// configuration: "current", "outdated" (run the install command again), or "unknown" (never fetched since tracking).
func xtcpFullView(ctx context.Context, db database, x xtcpSettings) (object, error) {
	view := xtcpView(x)
	mappings, err := xtcpMappings(ctx, db, x)
	if err != nil {
		return nil, err
	}
	view["mappings"] = mappings
	view["delivered_at"] = x.DeliveredAt
	switch {
	case x.DeliveredSHA256 == "":
		view["frpc_state"] = "unknown"
	case x.DeliveredSHA256 == xtcpFingerprint(x, mappings):
		view["frpc_state"] = "current"
	default:
		view["frpc_state"] = "outdated"
	}
	return view, nil
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
	if err != nil {
		return response{}, err
	}
	view, err := xtcpFullView(r.Context(), a.store.pool, x)
	if err != nil {
		return response{}, err
	}
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

// xtcpFrpcConfig serves the calling host's own frpc configuration (identified by its agent token) and records the
// fingerprint it served, so the console can tell when the host needs the install command again.
func (a *api) xtcpFrpcConfig(r *apiRequest) (response, error) {
	q := r.URL.Query()
	caFile, logFile := q.Get("ca_file"), q.Get("log_file")
	ctx := r.Context()
	var x xtcpSettings
	var mappings []xtcpMapping
	found := false
	err := a.store.snapshot(ctx, func(tx pgx.Tx) error {
		var err error
		if x, found, err = getXTCP(ctx, tx, r.Agent); err != nil || !found {
			return err
		}
		mappings, err = xtcpMappings(ctx, tx, x)
		return err
	})
	if err != nil || !found {
		return noContent, err
	}
	if !xtcpPathPattern.MatchString(caFile) || (logFile != "" && !xtcpPathPattern.MatchString(logFile)) {
		return response{}, failure(400, "ca_file (and log_file) must be absolute paths without quotes")
	}
	if _, err := a.store.pool.Exec(ctx, "UPDATE host_xtcp SET delivered_sha256 = $2, delivered_at = $3 WHERE host = $1",
		x.Host, xtcpFingerprint(x, mappings), a.store.now()); err != nil {
		return response{}, err
	}
	return response{status: 200, body: []byte(renderFrpcTOML(x, mappings, caFile, logFile)), contentType: "text/plain; charset=utf-8"}, nil
}

// xtcpVisitor returns one user's visitor configuration. It holds that user's scoped secret key only.
func (a *api) xtcpVisitor(r *apiRequest) (response, error) {
	name := r.PathValue("name")
	q := r.URL.Query()
	bindAddr := q.Get("bind_addr")
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}
	if _, err := ipv4(bindAddr); err != nil {
		return response{}, failure(400, "bind_addr must be an IPv4 address")
	}
	caFile := q.Get("ca_file")
	if caFile == "" {
		caFile = "frp-ca.pem"
	}
	if !xtcpVisitorCAPattern.MatchString(caFile) {
		return response{}, failure(400, "ca_file must be a path without quotes")
	}
	ctx := r.Context()
	var out object
	err := a.store.snapshot(ctx, func(tx pgx.Tx) error {
		user, err := getUser(ctx, tx, name)
		if err != nil {
			return err
		}
		if user.Host == nil {
			return failure(409, "user %s holds no egress IP", name)
		}
		x, found, err := getXTCP(ctx, tx, *user.Host)
		if err != nil {
			return err
		}
		if !found {
			return failure(409, "host %s uses the public entry, not XTCP", *user.Host)
		}
		mappings, err := xtcpMappings(ctx, tx, x)
		if err != nil {
			return err
		}
		for _, m := range mappings {
			if m.User == name {
				out = object{"user": name, "host": x.Host, "proxy_name": m.ProxyName, "primary": m.Primary,
					"bind_addr": bindAddr, "bind_port": m.Port, "secret_key": m.secretKey, "ca_pem": x.CAPEM,
					"frpc_toml": renderVisitorTOML(x, m, bindAddr, caFile)}
				return nil
			}
		}
		return failure(409, "user %s has no XTCP mapping on host %s", name, x.Host)
	})
	return ok(out, err)
}

func (a *api) xtcpCA(r *apiRequest) (response, error) {
	x, ok, err := getXTCP(r.Context(), a.store.pool, r.Agent)
	if err != nil || !ok {
		return noContent, err
	}
	return response{status: 200, body: []byte(x.CAPEM), contentType: "application/x-pem-file"}, nil
}
