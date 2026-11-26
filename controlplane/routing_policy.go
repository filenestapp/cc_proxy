package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"slices"
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

func (p *clientPolicy) applyDomainGroups(exactSupported bool) error {
	if len(p.DomainGroups) == 0 {
		return nil
	}
	suffixes := slices.Clone(p.DomainSuffix)
	var exact []string
	for _, id := range routingGroupIDs {
		group := p.DomainGroups[id]
		if group.Enabled {
			suffixes = append(suffixes, group.DomainSuffix...)
			if exactSupported {
				exact = append(exact, group.Domain...)
			}
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

// An older settings client can replace the flat policy without losing groups.
// Check the combined limit in the same write transaction that saves the policy.
func validateRoutingPolicyChange(ctx context.Context, db database, value fields) error {
	groups, supplied := value["domain_groups"]
	if !supplied {
		if err := db.QueryRow(ctx, "SELECT COALESCE((SELECT value->'domain_groups' FROM settings WHERE key='client_policy'), 'null'::jsonb)").Scan(&groups); err != nil {
			return err
		}
		if len(groups) == 0 || string(groups) == "null" {
			return nil
		}
		value["domain_groups"] = groups
	}
	var policy clientPolicy
	if err := json.Unmarshal(groups, &policy.DomainGroups); err != nil {
		return err
	}
	if suffixes := value["domain_suffix"]; len(suffixes) != 0 {
		if err := json.Unmarshal(suffixes, &policy.DomainSuffix); err != nil {
			return err
		}
	}
	return policy.applyDomainGroups(true)
}
