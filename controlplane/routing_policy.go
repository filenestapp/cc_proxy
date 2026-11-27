package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"maps"
	"slices"
	"strings"
)

//go:embed routing-presets.json
var routingPresets json.RawMessage

var routingGroupIDs = [...]string{"claude", "openai", "gemini"}

// Keep each rendered list within the client's runtime limit.
const maxClientDomainRules = 500

type routingGroup struct {
	Enabled      bool     `json:"enabled"`
	Domain       []string `json:"domain"`
	DomainSuffix []string `json:"domain_suffix"`
}

func normalizeRoutingGroups(raw json.RawMessage) (map[string]routingGroup, error) {
	var data map[string]json.RawMessage
	if err := json.Unmarshal(raw, &data); err != nil || data == nil {
		return nil, failure(400, "domain_groups must be an object")
	}
	for id := range data {
		if !slices.Contains(routingGroupIDs[:], id) {
			return nil, failure(400, "unknown routing group %s", id)
		}
	}
	groups := make(map[string]routingGroup, len(data))
	for _, id := range routingGroupIDs {
		rawGroup, ok := data[id]
		if !ok {
			continue
		}
		var group *routingGroup
		decoder := json.NewDecoder(bytes.NewReader(rawGroup))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&group); err != nil || group == nil {
			return nil, failure(400, "invalid routing group %s", id)
		}
		var err error
		group.Domain, err = normalizeProxiedDomains(group.Domain)
		if err != nil {
			return nil, failure(400, "routing group %s exact domains: %v", id, err)
		}
		group.DomainSuffix, err = normalizeProxiedDomains(group.DomainSuffix)
		if err != nil {
			return nil, failure(400, "routing group %s domain suffixes: %v", id, err)
		}
		group.Domain = uniqueDomains(group.Domain)
		group.DomainSuffix = uniqueDomains(group.DomainSuffix)
		if len(group.Domain) > maxClientDomainRules || len(group.DomainSuffix) > maxClientDomainRules {
			return nil, failure(400, "routing group %s has too many domain rules", id)
		}
		groups[id] = *group
	}
	return groups, nil
}

func uniqueDomains(domains []string) []string {
	seen := make(map[string]bool, len(domains))
	unique := make([]string, 0, len(domains))
	for _, domain := range domains {
		if !seen[domain] {
			seen[domain] = true
			unique = append(unique, domain)
		}
	}
	return unique
}

func (p *clientPolicy) applyDomainGroups() error {
	if len(p.DomainGroups) == 0 {
		return nil
	}
	suffixes := slices.Clone(p.DomainSuffix)
	var exact []string
	for _, id := range routingGroupIDs {
		group := p.DomainGroups[id]
		if group.Enabled {
			suffixes = append(suffixes, group.DomainSuffix...)
			exact = append(exact, group.Domain...)
		}
	}
	if len(suffixes) == len(p.DomainSuffix) && len(exact) == 0 {
		return nil
	}
	p.DomainSuffix = uniqueDomains(suffixes)
	p.DomainExact = uniqueDomains(exact)
	if len(p.DomainSuffix) > maxClientDomainRules || len(p.DomainExact) > maxClientDomainRules {
		return failure(400, "enabled routing groups exceed the client domain rule limit")
	}
	return nil
}

// Older settings clients can replace the flat policy while retaining grouped routes and STUN settings.
// Check the count and wire size in the same write transaction that saves the policy.
func validateRoutingPolicyChange(ctx context.Context, db database, value fields) error {
	var saved fields
	if err := db.QueryRow(ctx, "SELECT COALESCE((SELECT value FROM settings WHERE key='client_policy'), '{}'::jsonb)").Scan(&saved); err != nil {
		return err
	}
	if stun, supplied := value["stun"]; supplied && len(value) == 1 {
		maps.Copy(value, saved)
		value["stun"] = stun
	} else {
		// Older policy writers omit fields they do not support.
		for _, field := range []string{"domain_groups", "stun"} {
			if _, supplied := value[field]; !supplied && len(saved[field]) != 0 && string(saved[field]) != "null" {
				value[field] = saved[field]
			}
		}
	}
	if _, grouped := value["domain_groups"]; !grouped {
		return nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	policy := clientPolicy{BlockQUIC: true, DirectDNS: "dhcp"}
	if err := json.Unmarshal(raw, &policy); err != nil {
		return failure(400, "invalid client_policy: %s", err)
	}
	if len(policy.DomainGroups) == 0 {
		return nil
	}
	if err := policy.applyDomainGroups(); err != nil {
		return err
	}
	hasDomains := len(policy.DomainSuffix)+len(policy.DomainExact) != 0
	if !hasDomains && len(policy.ProcessName)+len(policy.ProcessPath) == 0 {
		return nil
	}

	// Reserve space for the longest client-supported endpoint and credential fields.
	// These fields use ASCII characters that require no JSON escaping.
	longestHostname := strings.Repeat("a", maxHostnameBytes)
	entry := host{
		PublicHost: longestHostname, ServerName: longestHostname,
		RealityPublic: strings.Repeat("a", 43), ShortID: strings.Repeat("a", 16),
	}
	user := boundUser{Port: 65535}
	device := credential{UUID: strings.Repeat("a", 36)}
	// The default STUN policy gives the longest app-mode config. Reserve space for it
	// even when an administrator has selected direct.
	policy.STUN = "proxy"
	if _, err := renderClientConfig(entry, user, device, policy, "app", clientConfigCapabilities{exactDomains: true, stun: true}); err != nil {
		return err
	}
	if hasDomains {
		_, err := renderClientConfig(entry, user, device, policy, "domain", clientConfigCapabilities{exactDomains: true})
		return err
	}
	return nil
}
