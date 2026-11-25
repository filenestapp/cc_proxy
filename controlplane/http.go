package main

import (
	"context"
	"crypto/hmac"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

//go:embed console.html
var consolePage []byte

const (
	sessionCookie          = "cp_session"
	customerSessionCookie  = "aifree_session"
	defaultPublicURL       = "https://cp.aifree.sg"
	controlPlaneHost       = "cp.aifree.sg"
	legacyControlPlaneHost = "ccproxy.macmini.sg"
	customerHost           = "app.aifree.sg"
)

type object = map[string]any
type fields map[string]json.RawMessage

type httpError struct {
	status  int
	message string
	code    string
}

func (e *httpError) Error() string { return e.message }

func failure(status int, format string, args ...any) error {
	return &httpError{status: status, message: fmt.Sprintf(format, args...)}
}

func failureCode(status int, code, format string, args ...any) error {
	return &httpError{status: status, message: fmt.Sprintf(format, args...), code: code}
}

func statusOf(err error) int {
	var problem *httpError
	if errors.As(err, &problem) {
		return problem.status
	}
	return http.StatusInternalServerError
}

// The original API accepted both JSON integers and decimal strings for ports and counts.
type integer int

func (n *integer) UnmarshalJSON(data []byte) error {
	value := string(data)
	if len(data) > 0 && data[0] == '"' {
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
	}
	i, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return errors.New("expected an integer")
	}
	*n = integer(i)
	return nil
}

type apiRequest struct {
	*http.Request
	Body     fields
	raw      []byte
	Address  string
	Token    string
	Agent    string
	Device   deviceIdentity
	Session  adminSession
	Customer customerSession
}

func (r *apiRequest) decode(dst any, required ...string) error {
	for _, key := range required {
		if len(r.Body[key]) == 0 {
			return failure(400, "missing field %q", key)
		}
	}
	if len(r.raw) > 0 {
		if err := json.Unmarshal(r.raw, dst); err != nil {
			return failure(400, "invalid request: %s", err)
		}
	}
	return nil
}

type response struct {
	status      int
	body        any
	contentType string
	etag        string
	cookie      *http.Cookie
}

func ok(body any, err error) (response, error) {
	return response{status: 200, body: body}, err
}

func created(body any, err error) (response, error) {
	return response{status: 201, body: body}, err
}

type endpoint func(*apiRequest) (response, error)

type api struct {
	store          *store
	mux            *http.ServeMux
	adminToken     string
	probeToken     string
	trustedProxies []netip.Prefix
	limiter        loginLimiter
	actions        accountActionLimiter
	mail           mailSender
	served         servedCache
	publicURL      string
}

func newAPI(s *store, adminToken, probeToken string, proxies []netip.Prefix) http.Handler {
	return newAPIWithPublicURL(s, adminToken, probeToken, proxies, defaultPublicURL)
}

func newAPIWithMail(s *store, adminToken, probeToken string, proxies []netip.Prefix, mail mailSender) http.Handler {
	return newAPIWithMailAndPublicURL(s, adminToken, probeToken, proxies, mail, defaultPublicURL)
}

func newAPIWithPublicURL(s *store, adminToken, probeToken string, proxies []netip.Prefix, publicURL string) http.Handler {
	return newAPIWithMailAndPublicURL(s, adminToken, probeToken, proxies, newCloudMailSenderFromEnv(), publicURL)
}

func newAPIWithMailAndPublicURL(s *store, adminToken, probeToken string, proxies []netip.Prefix, mail mailSender, publicURL string) http.Handler {
	a := &api{
		store: s, mux: http.NewServeMux(), adminToken: adminToken, probeToken: probeToken, trustedProxies: proxies,
		limiter: loginLimiter{failures: make(map[string][]time.Time)},
		actions: accountActionLimiter{hits: make(map[string][]time.Time)}, mail: mail, publicURL: publicURL,
	}
	a.bind("GET /healthz", "", "", a.health)
	a.bind("POST /v1/login", "", "", a.login)
	a.bind("GET /v1/me", "device", "", a.me)
	a.bind("GET /v1/config", "device", "", a.deviceConfig)
	a.bind("POST /v1/logout", "device", "", a.deviceLogout)
	a.bind("GET /agent/ips", "agent", "", a.agentIPs)
	a.bind("GET /agent/server-config", "agent", "", a.agentConfig)
	a.bind("GET /agent/probe-targets", "agent", "", a.agentTargets)
	a.bind("POST /agent/report", "agent", "", a.agentReport)
	a.bind("POST /agent/usage", "agent", "", a.agentUsage)
	a.bind("GET /probe/targets", "probe", "", a.probeTargets)
	a.bind("POST /probe/report", "probe", "", a.probeReport)
	for _, pattern := range []string{"GET /{$}", "GET /console", "GET /console/{$}", "GET /dashboard", "GET /dashboard/{$}"} {
		a.bind(pattern, "", "", a.console)
	}
	a.adminRoutes()
	a.accountRoutes()
	a.accountPageRoutes()
	a.installRoutes()
	a.agentUpdateRoutes()
	a.xtcpRoutes()
	a.mux.HandleFunc("/", noRoute)
	return routeByHost(a.mux)
}

func noRoute(w http.ResponseWriter, _ *http.Request) {
	sendResponse(w, response{status: 404, body: object{"error": "no route"}})
}

func routeByHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch requestHost(r.Host) {
		case customerHost:
			if !isCustomerRoute(r.URL.Path) {
				noRoute(w, r)
				return
			}
		case controlPlaneHost, legacyControlPlaneHost:
			if isCustomerRoute(r.URL.Path) {
				noRoute(w, r)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func requestHost(host string) string {
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func isCustomerRoute(path string) bool {
	return path == "/account" || strings.HasPrefix(path, "/account/") || strings.HasPrefix(path, "/v1/account/")
}

func (a *api) bind(pattern, role, auditAction string, fn endpoint) {
	readJSON := strings.HasPrefix(pattern, "POST ") || strings.HasPrefix(pattern, "PUT ")
	a.bindWithBody(pattern, role, auditAction, fn, readJSON)
}

func (a *api) bindWithBody(pattern, role, auditAction string, fn endpoint, readJSON bool) {
	a.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		req := &apiRequest{Request: r, Address: a.clientIP(r)}
		handle := func() (response, error) {
			if err := a.authorize(req, role); err != nil {
				return response{}, err
			}
			if readJSON {
				if err := readBody(w, req); err != nil {
					return response{}, err
				}
			}
			return fn(req)
		}

		out, err := handle()
		if err != nil {
			status, message := statusOf(err), err.Error()
			if status == 500 {
				log.Printf("%s %s: %v", r.Method, pattern, err)
				message = "internal server error"
			}
			body := object{"error": message}
			var problem *httpError
			if errors.As(err, &problem) && problem.code != "" {
				body["code"] = problem.code
			}
			out = response{status: status, body: body}
		} else if auditAction != "" {
			var detail string
			if len(req.Body) != 0 {
				var doc any
				if json.Unmarshal(req.raw, &doc) == nil {
					redacted, _ := json.Marshal(scrub(doc))
					detail = string(redacted)
				}
			}
			a.writeAudit(req, req.Session.Admin, r.Method+" "+auditAction, r.URL.Path, detail)
		}
		if err == nil && role == "customer" && out.cookie == nil {
			out.cookie = a.customerCookie(req, customerCookieValue(r), int(customerSessionTTL.Seconds()))
		}
		sendResponse(w, out)
	})
}

func readBody(w http.ResponseWriter, req *apiRequest) error {
	data, err := io.ReadAll(http.MaxBytesReader(w, req.Request.Body, 1<<20))
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return failure(413, "body too large")
	}
	if err != nil {
		return failure(400, "could not read request body")
	}
	if len(data) == 0 {
		req.Body = fields{}
		return nil
	}
	if !json.Valid(data) {
		return failure(400, "body is not JSON")
	}
	if err := json.Unmarshal(data, &req.Body); err != nil || req.Body == nil {
		return failure(400, "body must be a JSON object")
	}
	req.raw = data
	return nil
}

func sendResponse(w http.ResponseWriter, resp response) {
	headers := w.Header()
	headers.Set("Cache-Control", "no-store")
	headers.Set("X-Content-Type-Options", "nosniff")
	if resp.etag != "" {
		headers.Set("ETag", `"`+resp.etag+`"`)
	}
	if resp.cookie != nil {
		http.SetCookie(w, resp.cookie)
	}
	if resp.status == http.StatusNotModified || resp.status == http.StatusNoContent {
		w.WriteHeader(resp.status)
		return
	}
	var body []byte
	if resp.contentType == "" {
		data, err := json.Marshal(resp.body)
		if err != nil {
			resp.status = 500
			data = []byte(`{"error":"cannot encode response"}`)
			log.Printf("encode HTTP response: %v", err)
		}
		body, resp.contentType = append(data, '\n'), "application/json"
	} else {
		body = resp.body.([]byte)
	}
	if strings.HasPrefix(resp.contentType, "text/html") {
		headers.Set("X-Frame-Options", "DENY")
		headers.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; "+
			"style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
	}
	headers.Set("Content-Type", resp.contentType)
	headers.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(resp.status)
	w.Write(body)
}

func (a *api) authorize(r *apiRequest, role string) error {
	if role == "" {
		return nil
	}
	if token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		r.Token = token
	}
	ctx := r.Context()
	switch role {
	case "admin":
		if r.Token != "" && equalSecret(r.Token, a.adminToken) {
			r.Session.Admin = "api-token"
			return nil
		}
		if cookie := cookieValue(r.Request); cookie != "" {
			session, err := a.store.session(ctx, cookie)
			if err == nil {
				if r.Method != http.MethodGet && r.Method != http.MethodHead && !equalSecret(r.Header.Get("X-CSRF-Token"), session.CSRF) {
					return failure(403, "missing or wrong CSRF token")
				}
				r.Session = session
				return nil
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
	case "customer":
		if cookie := customerCookieValue(r.Request); cookie != "" {
			session, err := a.store.customerSession(ctx, cookie)
			if err == nil {
				if r.Method != http.MethodGet && r.Method != http.MethodHead && !equalSecret(r.Header.Get("X-CSRF-Token"), session.CSRF) {
					return failureCode(403, "csrf", "missing or wrong CSRF token")
				}
				if err := a.store.touchCustomerSession(ctx, cookie); err != nil {
					return err
				}
				r.Customer = session
				return nil
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
	case "device":
		if r.Token != "" {
			var err error
			r.Device, err = a.store.identifyDevice(ctx, r.Token)
			return err
		}
	case "agent":
		if r.Token != "" {
			err := a.store.pool.QueryRow(ctx, "SELECT name FROM hosts WHERE agent_token_hash = $1", hashToken(r.Token)).Scan(&r.Agent)
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
	case "probe":
		if r.Token != "" && equalSecret(r.Token, a.probeToken) {
			return nil
		}
	}
	return failure(401, "unauthorized")
}

func equalSecret(given, expected string) bool {
	return expected != "" && hmac.Equal([]byte(given), []byte(expected))
}

func cookieValue(r *http.Request) string {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		return cookie.Value
	}
	return ""
}

func customerCookieValue(r *http.Request) string {
	if cookie, err := r.Cookie(customerSessionCookie); err == nil {
		return cookie.Value
	}
	return ""
}

func parseProxies(values []string) ([]netip.Prefix, error) {
	proxies := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if ip, err := netip.ParseAddr(value); err == nil {
			ip = ip.Unmap()
			proxies = append(proxies, netip.PrefixFrom(ip, ip.BitLen()))
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy %q: %w", value, err)
		}
		proxies = append(proxies, prefix.Masked())
	}
	return proxies, nil
}

func peerIP(r *http.Request) netip.Addr {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	ip, _ := netip.ParseAddr(host)
	return ip.Unmap()
}

func (a *api) trusted(ip netip.Addr) bool {
	for _, network := range a.trustedProxies {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (a *api) clientIP(r *http.Request) string {
	peer := peerIP(r)
	if !a.trusted(peer) {
		return peer.String()
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(hops[i])
		if hop == "" {
			continue
		}
		addr, err := netip.ParseAddr(hop)
		if err != nil {
			return peer.String()
		}
		if !a.trusted(addr.Unmap()) {
			return addr.Unmap().String()
		}
	}
	return peer.String()
}

func (a *api) sessionCookie(r *apiRequest, token string, maxAge int) *http.Cookie {
	secure := r.TLS != nil || (a.trusted(peerIP(r.Request)) && r.Header.Get("X-Forwarded-Proto") == "https")
	return &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, Secure: secure,
		SameSite: http.SameSiteStrictMode, MaxAge: maxAge}
}

func (a *api) customerCookie(r *apiRequest, token string, maxAge int) *http.Cookie {
	secure := r.TLS != nil || (a.trusted(peerIP(r.Request)) && r.Header.Get("X-Forwarded-Proto") == "https")
	return &http.Cookie{Name: customerSessionCookie, Value: token, Path: "/", HttpOnly: true, Secure: secure,
		SameSite: http.SameSiteLaxMode, MaxAge: maxAge}
}

func (a *api) writeAudit(r *apiRequest, actor, action, target, detail string) {
	if err := a.store.audit(r.Context(), actor, action, target, detail, r.Address); err != nil {
		log.Printf("write audit log: %v", err)
	}
}

func configResponse(r *apiRequest, cfg renderedConfig) response {
	for _, header := range r.Header.Values("If-None-Match") {
		for _, value := range strings.Split(header, ",") {
			value = strings.TrimPrefix(strings.TrimSpace(value), "W/")
			if value == "*" || strings.Trim(value, `"`) == cfg.ETag {
				return response{status: 304, etag: cfg.ETag}
			}
		}
	}
	return response{status: 200, body: cfg.Body, contentType: "application/json", etag: cfg.ETag}
}

func (a *api) health(r *apiRequest) (response, error) {
	v, err := version(r.Context(), a.store.pool)
	return ok(object{"ok": true, "version": v}, err)
}

func (a *api) console(_ *apiRequest) (response, error) {
	return response{status: 200, body: consolePage, contentType: "text/html; charset=utf-8"}, nil
}

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (a *api) login(r *apiRequest) (response, error) {
	var body struct {
		credentials
		Device   string `json:"device"`
		Platform string `json:"platform"`
	}
	if err := r.decode(&body, "username", "password", "device"); err != nil {
		return response{}, err
	}
	keys := []string{"user:" + body.Username, "addr:" + r.Address}
	if a.limiter.blocked(a.store.clock(), keys...) {
		return response{}, failure(429, "too many failed sign-ins; try again later")
	}
	if strings.Contains(body.Username, "@") {
		customer, err := a.store.checkCustomerCredentials(r.Context(), body.Username, body.Password)
		if err != nil && statusOf(err) == http.StatusUnauthorized {
			a.limiter.fail(a.store.clock(), keys...)
		}
		if err != nil {
			return response{}, err
		}
		token, user, err := a.store.loginCustomerProxy(r.Context(), customer.ID, body.Device, body.Platform)
		if err != nil {
			return response{}, err
		}
		return ok(struct {
			userSummary
			Token  string `json:"token"`
			Device string `json:"device"`
		}{user, token, body.Device}, nil)
	}
	token, user, err := a.store.loginUser(r.Context(), body.Username, body.Password, body.Device, body.Platform)
	if err != nil && statusOf(err) == 401 {
		a.limiter.fail(a.store.clock(), keys...)
	}
	return ok(struct {
		userSummary
		Token  string `json:"token"`
		Device string `json:"device"`
	}{user, token, body.Device}, err)
}

func (a *api) me(r *apiRequest) (response, error) {
	user, err := userInfo(r.Context(), a.store.pool, r.Device.User)
	return ok(struct {
		userSummary
		Device string `json:"device"`
	}{user, r.Device.Name}, err)
}

func (a *api) deviceConfig(r *apiRequest) (response, error) {
	query := r.URL.Query()
	mode := query.Get("mode")
	if !query.Has("mode") {
		mode = "app"
	}
	switch mode {
	case "proxy", "domain", "app":
	default:
		return response{}, failure(400, "mode must be one of proxy, domain, app")
	}
	var cfg renderedConfig
	err := a.store.snapshot(r.Context(), func(tx pgx.Tx) error {
		var err error
		cfg, err = clientConfig(r.Context(), tx, r.Device, mode)
		return err
	})
	return configResponse(r, cfg), err
}

func (a *api) deviceLogout(r *apiRequest) (response, error) {
	err := a.store.logoutDevice(r.Context(), r.Device)
	return ok(object{"signed_out": r.Device.Name}, err)
}

func (a *api) agentConfig(r *apiRequest) (response, error) {
	ctx := r.Context()
	var cfg renderedConfig
	var served []servedDevice
	err := a.store.snapshot(ctx, func(tx pgx.Tx) error {
		h, err := getHost(ctx, tx, r.Agent)
		if err != nil {
			return err
		}
		if cfg, err = serverConfig(ctx, tx, h); err != nil {
			return err
		}
		served, err = servedDevices(ctx, tx, h.Name)
		return err
	})
	if err == nil {
		a.recordServed(ctx, r.Agent, served) // lets the host report these devices' traffic later
	}
	return configResponse(r, cfg), err
}

func (a *api) agentIPs(r *apiRequest) (response, error) {
	ips, err := columnOf[string](r.Context(), a.store.pool,
		"SELECT host(ip) FROM egress_ips WHERE host = $1 AND NOT banned ORDER BY ip", r.Agent)
	var lines strings.Builder
	for _, ip := range ips {
		lines.WriteString(ip)
		lines.WriteByte('\n')
	}
	return response{status: 200, body: []byte(lines.String()), contentType: "text/plain"}, err
}

func (a *api) monitorSettings(ctx context.Context) (monitorSettings, error) {
	cfg, err := loadSettings(ctx, a.store.pool)
	if err != nil {
		return monitorSettings{}, err
	}
	return decodeMonitor(cfg)
}

func (a *api) agentTargets(r *apiRequest) (response, error) {
	cfg, err := a.monitorSettings(r.Context())
	return ok(object{"egress_targets": orEmpty(cfg.Targets)}, err)
}

func (a *api) agentReport(r *apiRequest) (response, error) {
	var body struct {
		heartbeat
		Probes []probeInput `json:"probes"`
	}
	if err := r.decode(&body); err != nil {
		return response{}, err
	}
	if string(r.Body["probes"]) == "null" {
		return response{}, failure(400, "probes must be a list")
	}
	address, _ := netip.ParseAddr(r.Address)
	if a.trusted(address) {
		// With no usable forwarding chain, clientIP falls back to the proxy itself.
		address = netip.Addr{}
	}
	err := a.store.reportAgent(r.Context(), r.Agent, r.Token, address, body.heartbeat, body.Probes)
	return ok(object{"recorded": len(body.Probes)}, err)
}

func (a *api) probeTargets(r *apiRequest) (response, error) {
	ctx := r.Context()
	cfg, err := a.monitorSettings(ctx)
	if err != nil {
		return response{}, err
	}
	entries, err := listEntries(ctx, a.store.pool, cfg)
	return ok(object{"entries": entries}, err)
}

func (a *api) probeReport(r *apiRequest) (response, error) {
	var body struct {
		Vantage string       `json:"vantage"`
		Results []probeInput `json:"results"`
	}
	if err := r.decode(&body, "vantage", "results"); err != nil {
		return response{}, err
	}
	if body.Results == nil {
		return response{}, failure(400, "results must be a list")
	}
	ctx := r.Context()
	err := pgx.BeginFunc(ctx, a.store.pool, func(tx pgx.Tx) error {
		return a.store.recordProbes(ctx, tx, "entry", body.Vantage, body.Results)
	})
	return ok(object{"recorded": len(body.Results)}, err)
}
