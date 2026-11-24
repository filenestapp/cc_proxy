package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf16"

	"github.com/jackc/pgx/v5"
)

const (
	vlessFlow   = "xtls-rprx-vision"
	fakeIPRange = "198.18.0.0/15"
	tunAddress  = "172.19.0.1/30"
)

// Preserve the field order of the original wire format so existing ETags survive the database cutover.
type configField struct {
	name  string
	value any
}

type configObject []configField

func (obj configObject) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	b.WriteByte('{')
	for i, field := range obj {
		if i != 0 {
			b.WriteByte(',')
		}
		if err := enc.Encode(field.name); err != nil {
			return nil, err
		}
		b.Truncate(b.Len() - 1)
		b.WriteByte(':')
		if err := enc.Encode(field.value); err != nil {
			return nil, err
		}
		b.Truncate(b.Len() - 1)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

type renderedConfig struct {
	Body []byte
	ETag string
}

func renderConfig(cfg configObject) (renderedConfig, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(cfg); err != nil {
		return renderedConfig{}, err
	}
	var ascii strings.Builder
	for _, r := range b.String() {
		switch {
		case r < 0x7f:
			ascii.WriteByte(byte(r))
		case r <= 0xffff:
			fmt.Fprintf(&ascii, "\\u%04x", r)
		default:
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(&ascii, "\\u%04x\\u%04x", hi, lo)
		}
	}
	body := []byte(ascii.String())
	digest := sha256.Sum256(body)
	return renderedConfig{Body: body, ETag: hex.EncodeToString(digest[:10])}, nil
}

type boundUser struct {
	Name string
	IP   string
	Port int
}

type credential struct {
	User string
	Name string
	UUID string
}

func serverConfig(ctx context.Context, db database, h host) (renderedConfig, error) {
	users, err := rowsOf[boundUser](ctx, db, "SELECT name, host(egress_ip) AS ip, port FROM users WHERE host = $1 ORDER BY name", h.Name)
	if err != nil {
		return renderedConfig{}, err
	}
	devices, err := rowsOf[credential](ctx, db, `SELECT d.user_name AS "user", d.name, d.uuid::text AS uuid
		FROM devices d JOIN users u ON d.user_name = u.name WHERE u.host = $1 AND d.revoked_at IS NULL ORDER BY d.name`, h.Name)
	if err != nil {
		return renderedConfig{}, err
	}
	return renderConfig(buildServerConfig(h, users, devices))
}

func buildServerConfig(h host, users []boundUser, devices []credential) configObject {
	byUser := make(map[string][]configObject)
	for _, d := range devices {
		byUser[d.User] = append(byUser[d.User], configObject{
			{"name", d.User + "/" + d.Name}, {"uuid", d.UUID}, {"flow", vlessFlow},
		})
	}
	tls := configObject{
		{"enabled", true}, {"server_name", h.ServerName}, {"reality", configObject{
			{"enabled", true}, {"handshake", configObject{{"server", h.HandshakeServer}, {"server_port", h.HandshakePort}}},
			{"private_key", h.RealityPrivate}, {"short_id", []string{h.ShortID}},
		}},
	}
	rules := []configObject{
		{{"action", "sniff"}},
		{{"action", "resolve"}, {"strategy", "ipv4_only"}},
		{{"ip_cidr", []string{"::/0"}}, {"action", "reject"}},
	}
	if h.BlockPrivate {
		rules = append(rules, configObject{{"ip_is_private", true}, {"action", "reject"}})
	}
	if len(h.BlockCIDRs) != 0 {
		rules = append(rules, configObject{{"ip_cidr", h.BlockCIDRs}, {"action", "reject"}})
	}

	inbounds := make([]configObject, 0, len(users))
	outbounds := make([]configObject, 0)
	seenIPs := make(map[string]bool)
	for _, user := range users {
		inTag, outTag := "user-"+user.Name, "egress-"+user.IP
		inbounds = append(inbounds, configObject{{"type", "vless"}, {"tag", inTag}, {"listen", "::"},
			{"listen_port", user.Port}, {"users", orEmpty(byUser[user.Name])}, {"tls", tls}})
		rules = append(rules, configObject{{"inbound", []string{inTag}}, {"outbound", outTag}})
		if !seenIPs[user.IP] {
			outbounds = append(outbounds, configObject{{"type", "direct"}, {"tag", outTag}, {"inet4_bind_address", user.IP}})
			seenIPs[user.IP] = true
		}
	}
	outbounds = append(outbounds, configObject{{"type", "block"}, {"tag", "deny"}})
	return configObject{
		{"log", configObject{{"level", "info"}, {"timestamp", true}}},
		{"dns", configObject{{"servers", []configObject{{{"type", "local"}, {"tag", "local"}}}}, {"strategy", "ipv4_only"}}},
		{"inbounds", inbounds}, {"outbounds", outbounds},
		{"route", configObject{{"rules", rules}, {"final", "deny"},
			{"default_domain_resolver", configObject{{"server", "local"}, {"strategy", "ipv4_only"}}}}},
	}
}

type clientPolicy struct {
	DomainSuffix []string `json:"domain_suffix"`
	ProcessName  []string `json:"process_name"`
	ProcessPath  []string `json:"process_path"`
	BlockQUIC    bool     `json:"block_quic"`
	DirectDNS    string   `json:"direct_dns"`
}

var proxiedDomainLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func normalizeProxiedDomains(rules []string) ([]string, error) {
	if len(rules) == 0 {
		return rules, nil
	}
	domains := make([]string, 0, len(rules))
	for i, rule := range rules {
		domain := strings.TrimSpace(rule)
		if strings.Contains(domain, "://") {
			parsed, err := url.Parse(domain)
			if err != nil || parsed.User != nil ||
				(!strings.EqualFold(parsed.Scheme, "https") && !strings.EqualFold(parsed.Scheme, "http")) {
				return nil, failure(400, "proxied rule %d must be a domain or an HTTP(S) URL", i+1)
			}
			domain = parsed.Hostname()
		}
		domain = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(domain, "."), "."))
		labels := strings.Split(domain, ".")
		if len(domain) > 253 || len(labels) < 2 {
			return nil, failure(400, "proxied rule %d must contain a valid domain", i+1)
		}
		for _, label := range labels {
			if !proxiedDomainLabel.MatchString(label) {
				return nil, failure(400, "proxied rule %d must contain a valid domain", i+1)
			}
		}
		domains = append(domains, domain)
	}
	return domains, nil
}

func clientConfig(ctx context.Context, db database, identity deviceIdentity, mode string) (renderedConfig, error) {
	var u boundUser
	var h host
	var d credential
	var port *int
	var publicHost, serverName, publicKey, shortID *string
	err := db.QueryRow(ctx, `SELECT u.name, u.port, `+publicEntryHostSQL+`, h.server_name, h.reality_public, h.short_id, d.uuid::text
		FROM devices d JOIN users u ON u.name = d.user_name LEFT JOIN hosts h ON h.name = u.host
		WHERE d.token_hash = $1 AND d.revoked_at IS NULL`, identity.TokenHash).
		Scan(&u.Name, &port, &publicHost, &serverName, &publicKey, &shortID, &d.UUID)
	if errors.Is(err, pgx.ErrNoRows) {
		return renderedConfig{}, failure(401, "unauthorized")
	}
	if err != nil {
		return renderedConfig{}, err
	}
	if port == nil {
		return renderedConfig{}, failure(409, "no exit IP is assigned to %s yet; ask the admin", u.Name)
	}
	if *publicHost == "" {
		return renderedConfig{}, failure(409, "the exit host is waiting for a public IPv4 from its Agent")
	}
	u.Port = *port
	h.PublicHost, h.ServerName, h.RealityPublic, h.ShortID = *publicHost, *serverName, *publicKey, *shortID
	policy := clientPolicy{BlockQUIC: true, DirectDNS: "dhcp"}
	if mode != "proxy" {
		cfg, err := loadSettings(ctx, db)
		if err != nil {
			return renderedConfig{}, err
		}
		if err := json.Unmarshal(cfg.ClientPolicy, &policy); err != nil {
			return renderedConfig{}, failure(409, "invalid client_policy: %s", err)
		}
		policy.DomainSuffix, err = normalizeProxiedDomains(policy.DomainSuffix)
		if err != nil {
			return renderedConfig{}, err
		}
	}
	cfg, err := buildClientConfig(h, u, d, policy, mode)
	if err != nil {
		return renderedConfig{}, err
	}
	return renderConfig(cfg)
}

func buildClientConfig(h host, user boundUser, d credential, policy clientPolicy, mode string) (configObject, error) {
	outbounds := []configObject{{
		{"type", "vless"}, {"tag", "egress"}, {"server", h.PublicHost}, {"server_port", user.Port}, {"uuid", d.UUID},
		{"flow", vlessFlow}, {"tls", configObject{
			{"enabled", true}, {"server_name", h.ServerName},
			{"utls", configObject{{"enabled", true}, {"fingerprint", "chrome"}}},
			{"reality", configObject{{"enabled", true}, {"public_key", h.RealityPublic}, {"short_id", h.ShortID}}},
		}},
	}, {{"type", "direct"}, {"tag", "direct"}}}
	log := configObject{{"level", "warn"}, {"timestamp", true}}
	if mode == "proxy" {
		return configObject{
			{"log", log},
			{"inbounds", []configObject{{{"type", "mixed"}, {"tag", "local-in"}, {"listen", "127.0.0.1"}, {"listen_port", 2080}}}},
			{"outbounds", outbounds}, {"route", configObject{{"final", "egress"}}},
		}, nil
	}
	if len(policy.DomainSuffix) == 0 && mode == "domain" {
		return nil, failure(409, "client_policy.domain_suffix is empty; domain mode would tunnel nothing")
	}
	if len(policy.DomainSuffix)+len(policy.ProcessName)+len(policy.ProcessPath) == 0 {
		return nil, failure(409, "client_policy has no process or domain rules; app mode would tunnel nothing")
	}

	tun := configObject{{"type", "tun"}, {"tag", "tun-in"}, {"address", []string{tunAddress}}, {"auto_route", true}, {"stack", "mixed"}}
	if mode == "domain" {
		tun = append(tun, configField{"route_address", []string{fakeIPRange, "172.19.0.0/30"}})
	} else {
		tun = append(tun, configField{"strict_route", true})
	}
	dnsRules := make([]configObject, 0, 2)
	if len(policy.DomainSuffix) != 0 {
		dnsRules = append(dnsRules,
			configObject{{"domain_suffix", policy.DomainSuffix}, {"query_type", []string{"AAAA"}}, {"action", "predefined"}, {"rcode", "NOERROR"}},
			configObject{{"domain_suffix", policy.DomainSuffix}, {"server", "fakeip"}})
	}
	directDNS := configObject{{"type", policy.DirectDNS}, {"tag", "direct-dns"}}
	if policy.DirectDNS != "dhcp" && policy.DirectDNS != "local" {
		directDNS = configObject{{"type", "udp"}, {"tag", "direct-dns"}, {"server", policy.DirectDNS}}
	}
	dns := configObject{
		{"servers", []configObject{{{"type", "fakeip"}, {"tag", "fakeip"}, {"inet4_range", fakeIPRange}}, directDNS}},
		{"rules", dnsRules}, {"final", "direct-dns"},
	}
	rules := []configObject{{{"action", "sniff"}}, {{"protocol", "dns"}, {"action", "hijack-dns"}}}
	matchers := make([]configField, 0, 4)
	if len(policy.DomainSuffix) != 0 {
		matchers = append(matchers, configField{"domain_suffix", policy.DomainSuffix})
	}
	matchers = append(matchers, configField{"ip_cidr", []string{fakeIPRange}})
	if mode == "app" && len(policy.ProcessName) != 0 {
		matchers = append(matchers, configField{"process_name", policy.ProcessName})
	}
	if mode == "app" && len(policy.ProcessPath) != 0 {
		matchers = append(matchers, configField{"process_path", policy.ProcessPath})
	}
	if policy.BlockQUIC {
		for _, match := range matchers {
			rules = append(rules, configObject{match, {"network", "udp"}, {"port", 443}, {"action", "reject"}})
		}
	}
	for _, match := range matchers {
		rules = append(rules, configObject{match, {"outbound", "egress"}})
	}
	route := configObject{{"rules", rules}, {"final", "direct"}, {"auto_detect_interface", true}, {"default_domain_resolver", "direct-dns"}}
	if mode == "app" {
		route = append(route, configField{"find_process", true})
	}
	return configObject{
		{"log", log}, {"inbounds", []configObject{tun}}, {"outbounds", outbounds}, {"route", route}, {"dns", dns},
		{"experimental", configObject{{"cache_file", configObject{{"enabled", true}, {"store_fakeip", true}}}}},
	}, nil
}
