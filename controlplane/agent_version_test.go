package main

import (
	"net/netip"
	"testing"
)

func TestAgentVersionHeartbeatIsRetainedAndReportedInTopology(t *testing.T) {
	ctx := t.Context()
	s := testStore(t)
	first := testHost(t, s, "first", "192.0.2", 20443)
	second := testHost(t, s, "second", "198.51.100", 20443)

	require(t, s.reportAgent(ctx, "first", first, netip.Addr{}, heartbeat{AgentVersion: "agent-0a37adb7da36"}, nil))
	require(t, s.reportAgent(ctx, "second", second, netip.Addr{}, heartbeat{}, nil))

	settings, err := loadSettings(ctx, s.pool)
	require(t, err)
	monitor, err := decodeMonitor(settings)
	require(t, err)
	topology, err := s.topology(ctx, s.pool, monitor)
	require(t, err)
	versions := map[string]*string{}
	for _, agent := range topology.Agents {
		versions[agent.Name] = agent.AgentVersion
	}
	if got := versions["first"]; got == nil || *got != "agent-0a37adb7da36" {
		t.Fatalf("first host agent version = %v, want legacy value", got)
	}
	if got := versions["second"]; got != nil {
		t.Fatalf("older Agent should have no version, got %q", *got)
	}

	require(t, s.reportAgent(ctx, "first", first, netip.Addr{}, heartbeat{AgentVersion: "v0.1.0"}, nil))
	require(t, s.reportAgent(ctx, "second", second, netip.Addr{}, heartbeat{AgentVersion: "agent-second"}, nil))
	topology, err = s.topology(ctx, s.pool, monitor)
	require(t, err)
	versions = map[string]*string{}
	for _, agent := range topology.Agents {
		versions[agent.Name] = agent.AgentVersion
	}
	if got := versions["first"]; got == nil || *got != "v0.1.0" {
		t.Fatalf("updated Agent version = %v, want v0.1.0", got)
	}
	if got := versions["second"]; got == nil || *got != "agent-second" {
		t.Fatalf("second host agent version = %v, want agent-second", got)
	}

	// A pre-version Agent can return after a rollback or reinstall. Its successful
	// heartbeat must clear the current value instead of displaying a stale upgrade.
	require(t, s.reportAgent(ctx, "first", first, netip.Addr{}, heartbeat{}, nil))
	topology, err = s.topology(ctx, s.pool, monitor)
	require(t, err)
	for _, agent := range topology.Agents {
		if agent.Name == "first" && agent.AgentVersion != nil {
			t.Fatalf("legacy Agent heartbeat kept a stale version %q", *agent.AgentVersion)
		}
	}
}

func TestAgentVersionSchemaUpgradePreservesHeartbeats(t *testing.T) {
	ctx := t.Context()
	s := testStore(t)
	token := testHost(t, s, "legacy", "192.0.2", 20443)
	_, err := s.pool.Exec(ctx, "ALTER TABLE agents DROP COLUMN agent_version")
	require(t, err)
	require(t, s.initializeSchema(ctx))
	require(t, s.reportAgent(ctx, "legacy", token, netip.Addr{}, heartbeat{}, nil))
	require(t, s.initializeSchema(ctx))
}
